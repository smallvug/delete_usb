"""USB Secure Wiper — tkinter GUI.

메인 창 구성:
  - 디스크 목록 (Treeview)     : 연결된 USB/SATA 디스크 표시
  - 삭제 옵션                   : 빠른(1-pass) / 표준(3-pass), 검증, 파티션 제거
  - 진행률 바 + 로그            : 삭제 진행 상황 실시간 표시
  - 디스크 검사 (헥스 뷰어)     : 삭제 전후 raw 데이터를 색상으로 확인

스레딩 모델:
  - 삭제 작업은 워커 스레드에서 실행 (UI 블로킹 방지)
  - queue.Queue로 워커→UI 진행률 전달
  - root.after(100ms)로 큐 폴링 (tkinter는 단일 스레드)
"""

import logging
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from disk_wiper import (
    DiskWiper, SecureEraseInfo, VerifyResult, WipeConfig, WipeResult,
    ata_secure_erase, check_secure_erase,
    get_disk_size, read_disk_sectors, verify_disk_wipe,
)
from usb_detector import DriveInfo, refresh_drives

logger = logging.getLogger(__name__)

PASS_NAMES_KR = {
    "zeros": "제로 (0x00)",
    "ones": "원스 (0xFF)",
    "random": "랜덤",
}

# 다크 모드 색상 (clam 테마 기반)
_DARK = {
    "bg": "#2d2d2d",
    "fg": "#d4d4d4",
    "field": "#1e1e1e",
    "button": "#3d3d3d",
    "select": "#264f78",
    "tree_head": "#3d3d3d",
    "border": "#555555",
}


class SecureWiperApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("USB Secure Wiper")
        self.root.geometry("720x580")
        self.root.minsize(640, 500)

        self.drives: list[DriveInfo] = []
        self.wipe_thread: threading.Thread | None = None
        self.cancel_event = threading.Event()
        self.progress_queue: queue.Queue = queue.Queue()
        self.is_wiping = False
        self._wipe_start_time: float = 0  # 삭제 시작 시간 (예상 소요 시간 계산용)
        self._is_dark = False
        self._default_theme = ttk.Style().theme_use()

        self._build_ui()
        self._refresh_drives()
        self._poll_progress()

    def _center_window(self, win: tk.Toplevel, width: int, height: int):
        """Toplevel 창을 메인 창 중앙에 배치."""
        self.root.update_idletasks()
        rx = self.root.winfo_x()
        ry = self.root.winfo_y()
        rw = self.root.winfo_width()
        rh = self.root.winfo_height()
        x = rx + (rw - width) // 2
        y = ry + (rh - height) // 2
        win.geometry(f"{width}x{height}+{x}+{y}")

    # ── UI 구성 ──────────────────────────────────────────

    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)

        # 드라이브 목록 프레임
        drive_frame = ttk.LabelFrame(self.root, text=" 디스크 목록 ", padding=8)
        drive_frame.grid(row=0, column=0, padx=10, pady=(10, 4), sticky="nsew")
        drive_frame.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Treeview
        cols = ("num", "name", "size", "letter", "fs")
        self.tree = ttk.Treeview(drive_frame, columns=cols, show="headings", height=5)
        self.tree.heading("num", text="#")
        self.tree.heading("name", text="이름")
        self.tree.heading("size", text="용량")
        self.tree.heading("letter", text="드라이브")
        self.tree.heading("fs", text="파일시스템")
        self.tree.column("num", width=40, anchor="center")
        self.tree.column("name", width=220)
        self.tree.column("size", width=90, anchor="center")
        self.tree.column("letter", width=80, anchor="center")
        self.tree.column("fs", width=100, anchor="center")
        self.tree.grid(row=0, column=0, sticky="nsew")
        drive_frame.rowconfigure(0, weight=1)

        # 드라이브 문자 경고 태그 (C:, D: 등 익숙한 문자가 있으면 빨간색)
        self.tree.tag_configure("warn_letter", foreground="red")

        # 마우스 호버 시 상세 정보 툴팁
        self._tooltip = _TreeTooltip(self.tree)
        self.tree.bind("<Motion>", self._on_tree_motion)

        scrollbar = ttk.Scrollbar(drive_frame, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.btn_refresh = ttk.Button(drive_frame, text="새로고침", command=self._refresh_drives)
        self.btn_refresh.grid(row=1, column=0, columnspan=2, pady=(4, 0), sticky="e")

        # 옵션 프레임
        opt_frame = ttk.LabelFrame(self.root, text=" 삭제 옵션 ", padding=8)
        opt_frame.grid(row=1, column=0, padx=10, pady=4, sticky="ew")

        self.wipe_mode = tk.StringVar(value="standard")
        ttk.Radiobutton(opt_frame, text="빠른 삭제 (1 pass - zeros)", variable=self.wipe_mode, value="quick").grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(opt_frame, text="표준 삭제 (3 pass - zeros, ones, random)", variable=self.wipe_mode, value="standard").grid(row=1, column=0, sticky="w")
        ttk.Radiobutton(opt_frame, text="정밀 삭제 (7 pass - DoD 5220.22-M 방식)", variable=self.wipe_mode, value="thorough").grid(row=2, column=0, sticky="w")

        self.var_verify = tk.BooleanVar(value=True)
        self.var_clean = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt_frame, text="삭제 후 검증", variable=self.var_verify).grid(row=0, column=1, padx=(30, 0), sticky="w")
        ttk.Checkbutton(opt_frame, text="파티션 테이블 제거", variable=self.var_clean).grid(row=1, column=1, padx=(30, 0), sticky="w")

        # 진행률 프레임
        prog_frame = ttk.Frame(self.root, padding=(10, 4))
        prog_frame.grid(row=2, column=0, sticky="ew")
        prog_frame.columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(prog_frame, mode="determinate", maximum=100)
        self.progress.grid(row=0, column=0, sticky="ew")

        self.lbl_progress = ttk.Label(prog_frame, text="대기 중")
        self.lbl_progress.grid(row=1, column=0, sticky="w")

        # 로그 프레임
        log_frame = ttk.LabelFrame(self.root, text=" 로그 ", padding=4)
        log_frame.grid(row=3, column=0, padx=10, pady=4, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        self.root.rowconfigure(3, weight=1)

        self.log_text = tk.Text(log_frame, height=6, state="disabled", font=("Consolas", 9))
        self.log_text.grid(row=0, column=0, sticky="nsew")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)

        # 버튼 프레임
        btn_frame = ttk.Frame(self.root, padding=10)
        btn_frame.grid(row=4, column=0)

        self.btn_start = ttk.Button(btn_frame, text="삭제 시작", command=self._on_start_wipe)
        self.btn_start.grid(row=0, column=0, padx=8)

        self.btn_cancel = ttk.Button(btn_frame, text="취소", command=self._on_cancel, state="disabled")
        self.btn_cancel.grid(row=0, column=1, padx=8)

        self.btn_inspect = ttk.Button(btn_frame, text="디스크 검사", command=self._on_inspect)
        self.btn_inspect.grid(row=0, column=2, padx=8)

        self.btn_secure_erase = ttk.Button(btn_frame, text="Secure Erase", command=self._on_secure_erase)
        self.btn_secure_erase.grid(row=0, column=3, padx=8)

        self.btn_theme = ttk.Button(btn_frame, text="다크 모드", command=self._toggle_theme)
        self.btn_theme.grid(row=0, column=4, padx=8)

    # ── 툴팁 ──────────────────────────────────────────────

    # 알려진 시스템 드라이브 문자 (이 문자가 있으면 경고 표시)
    _WARN_LETTERS = {"C", "D"}

    def _on_tree_motion(self, event):
        """Treeview 위에서 마우스 이동 시 드라이브 상세 정보 툴팁 표시."""
        item = self.tree.identify_row(event.y)
        if not item:
            self._tooltip.hide()
            return
        drive = next((d for d in self.drives if str(d.disk_number) == item), None)
        if not drive:
            self._tooltip.hide()
            return
        lines = [
            f"Disk {drive.disk_number}: {drive.friendly_name}",
            f"모델: {drive.model or '(알 수 없음)'}",
            f"시리얼: {drive.serial_number or '(알 수 없음)'}",
            f"미디어: {drive.media_type or '(알 수 없음)'}",
            f"버스: {drive.bus_type}",
            f"용량: {drive.size_display}",
        ]
        if drive.partitions:
            for p in drive.partitions:
                lbl = p.label or ""
                lines.append(f"  {p.drive_letter or '-'}:  {p.size_gb:.1f} GB  {p.filesystem or '?'}  {lbl}")
        self._tooltip.show("\n".join(lines), event)

    # ── 드라이브 목록 ────────────────────────────────────

    def _refresh_drives(self):
        self.tree.delete(*self.tree.get_children())
        self._log("디스크 검색 중...")

        self.drives = refresh_drives()

        if not self.drives:
            self._log("연결된 디스크가 없습니다.")
            return

        for d in self.drives:
            letters = ", ".join(f"{l}:" for l in d.drive_letters) or "-"
            fs_list = ", ".join(p.filesystem or "?" for p in d.partitions) or "-"
            # 시스템 드라이브 문자(C:, D:)가 포함된 행은 빨간색 경고
            has_warn = any(l in self._WARN_LETTERS for l in d.drive_letters)
            tags = ("warn_letter",) if has_warn else ()
            self.tree.insert("", "end", iid=str(d.disk_number), values=(
                d.disk_number,
                d.friendly_name,
                d.size_display,
                letters,
                fs_list,
            ), tags=tags)

        self._log(f"{len(self.drives)}개의 디스크를 찾았습니다.")

    # ── 삭제 시작 ────────────────────────────────────────

    def _on_start_wipe(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("선택 필요", "삭제할 디스크를 선택해주세요.", parent=self.root)
            return

        disk_num = int(selected[0])
        drive = next((d for d in self.drives if d.disk_number == disk_num), None)
        if not drive:
            messagebox.showerror("오류", "선택한 드라이브를 찾을 수 없습니다.", parent=self.root)
            return

        # 2TB 초과 경고
        if drive.size_bytes > 2 * 1024**4:
            if not messagebox.askyesno(
                "용량 경고",
                f"이 드라이브의 용량은 {drive.size_display}로 매우 큽니다.\n"
                "삭제 대상이 맞는지 확인해주세요.\n\n계속하시겠습니까?",
                parent=self.root,
            ):
                return

        # 확인 다이얼로그
        if not self._confirm_wipe_dialog(drive):
            return

        # 설정 구성: 삭제 모드별 패스 횟수
        mode = self.wipe_mode.get()
        if mode == "quick":
            passes = ["zeros"]
        elif mode == "thorough":
            # DoD 5220.22-M 방식: 0x00 → 0xFF → random을 2회 반복 + 최종 random
            passes = ["zeros", "ones", "random", "zeros", "ones", "random", "random"]
        else:
            passes = ["zeros", "ones", "random"]

        config = WipeConfig(
            passes=passes,
            verify=self.var_verify.get(),
            clean_disk=self.var_clean.get(),
        )

        # 워커 스레드 시작
        self.is_wiping = True
        self._wipe_start_time = time.time()
        self.cancel_event.clear()
        self.btn_start.configure(state="disabled")
        self.btn_secure_erase.configure(state="disabled")
        self.btn_cancel.configure(state="normal")
        self.btn_refresh.configure(state="disabled")
        self.progress["value"] = 0

        self._log(f"Disk {disk_num}: {drive.friendly_name} ({drive.size_display}) 삭제 시작")

        self.wipe_thread = threading.Thread(
            target=self._wipe_worker,
            args=(disk_num, config),
            daemon=True,
        )
        self.wipe_thread.start()

    def _confirm_wipe_dialog(self, drive: DriveInfo, mode_text: str | None = None) -> bool:
        """'WIPE' 타이핑 확인 다이얼로그."""
        dialog = tk.Toplevel(self.root)
        dialog.title("삭제 확인")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        self._center_window(dialog, 420, 280)

        result = {"confirmed": False}

        if mode_text is None:
            _modes = {"quick": "빠른 (1 pass)", "standard": "표준 (3 pass)", "thorough": "정밀 (7 pass)"}
            mode = _modes.get(self.wipe_mode.get(), "표준 (3 pass)")
        else:
            mode = mode_text
        letters = ", ".join(f"{l}:" for l in drive.drive_letters) or "-"

        ttk.Label(dialog, text="⚠ 경고: 모든 데이터가 영구적으로 파괴됩니다!", font=("", 11, "bold"), foreground="red").pack(pady=(15, 10))

        info = (
            f"드라이브: {drive.friendly_name}\n"
            f"용량: {drive.size_display}\n"
            f"드라이브 문자: {letters}\n"
            f"삭제 모드: {mode}"
        )
        ttk.Label(dialog, text=info, justify="left").pack(padx=20, anchor="w")

        ttk.Label(dialog, text='확인하려면 "WIPE" 를 입력하세요:', font=("", 10)).pack(pady=(15, 4))

        entry = ttk.Entry(dialog, width=20, font=("", 12), justify="center")
        entry.pack()
        entry.focus_set()

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=15)

        def on_confirm():
            if entry.get().strip() == "WIPE":
                result["confirmed"] = True
                dialog.destroy()
            else:
                messagebox.showwarning("입력 오류", '"WIPE" 를 정확히 입력해주세요.', parent=dialog)
                entry.delete(0, "end")
                entry.focus_set()

        def on_cancel():
            dialog.destroy()

        ttk.Button(btn_frame, text="삭제 실행", command=on_confirm).grid(row=0, column=0, padx=8)
        ttk.Button(btn_frame, text="취소", command=on_cancel).grid(row=0, column=1, padx=8)
        entry.bind("<Return>", lambda e: on_confirm())

        dialog.wait_window()
        return result["confirmed"]

    # ── 워커 스레드 ──────────────────────────────────────

    def _wipe_worker(self, disk_number: int, config: WipeConfig):
        def callback(pass_num, pass_name, bytes_done, total_bytes, overall_pct):
            self.progress_queue.put(("progress", pass_num, pass_name, bytes_done, total_bytes, overall_pct))

        wiper = DiskWiper(disk_number, config)
        result = wiper.wipe(progress_callback=callback, cancel_event=self.cancel_event)

        # 삭제 성공 시 상세 검증
        if result.success and config.verify:
            self.progress_queue.put(("verify_start",))
            try:
                disk_size = get_disk_size(disk_number)
                result.verify_result = verify_disk_wipe(disk_number, disk_size)
            except Exception as e:
                logger.warning(f"상세 검증 실패: {e}")

        self.progress_queue.put(("done", result))

    def _poll_progress(self):
        """100ms마다 큐를 확인하여 UI 업데이트."""
        try:
            while True:
                msg = self.progress_queue.get_nowait()

                if msg[0] == "progress":
                    _, pass_num, pass_name, bytes_done, total_bytes, overall_pct = msg
                    self.progress["value"] = overall_pct
                    name_kr = PASS_NAMES_KR.get(pass_name, pass_name)
                    done_str = f"{bytes_done / (1024**3):.1f}" if bytes_done > 1024**3 else f"{bytes_done / (1024**2):.0f} MB"
                    total_str = f"{total_bytes / (1024**3):.1f} GB"
                    if bytes_done > 1024**3:
                        done_str += " GB"

                    # 예상 남은 시간 계산
                    eta_str = ""
                    if overall_pct > 0.5:
                        elapsed = time.time() - self._wipe_start_time
                        remaining = elapsed * (100 - overall_pct) / overall_pct
                        if remaining >= 3600:
                            eta_str = f"  남은 시간: {remaining / 3600:.1f}시간"
                        elif remaining >= 60:
                            eta_str = f"  남은 시간: {remaining / 60:.0f}분"
                        else:
                            eta_str = f"  남은 시간: {remaining:.0f}초"

                    self.lbl_progress.configure(
                        text=f"Pass {pass_num} ({name_kr}) — {done_str} / {total_str}  [{overall_pct:.0f}%]{eta_str}"
                    )

                elif msg[0] == "verify_start":
                    self.lbl_progress.configure(text="검증 중... (랜덤 섹터 샘플링)")

                elif msg[0] == "done":
                    result: WipeResult = msg[1]
                    self.is_wiping = False
                    self.btn_start.configure(state="normal")
                    self.btn_secure_erase.configure(state="normal")
                    self.btn_cancel.configure(state="disabled")
                    self.btn_refresh.configure(state="normal")

                    if result.success:
                        self.progress["value"] = 100
                        self.lbl_progress.configure(text="완료!")
                        self._log(f"✓ {result.message}")

                        if result.verify_result:
                            vr = result.verify_result
                            v_msg = (
                                f"{vr.total_samples}개 섹터 검사 → "
                                f"{vr.clean_samples}개 정상 ({vr.clean_pct:.0f}%)"
                            )
                            if vr.dirty_samples > 0:
                                v_msg += f", {vr.dirty_samples}개 의심"
                            self._log(f"  검증: {v_msg}")
                            full = f"{result.message}\n\n[검증 결과]\n{v_msg}"
                            if vr.clean_pct >= 100:
                                messagebox.showinfo("완료", full, parent=self.root)
                            else:
                                messagebox.showwarning("완료 (검증 주의)", full, parent=self.root)
                        else:
                            messagebox.showinfo("완료", result.message, parent=self.root)
                    elif result.cancelled:
                        self.lbl_progress.configure(text="취소됨")
                        self._log(f"취소: {result.message}")
                    else:
                        self.lbl_progress.configure(text="실패")
                        self._log(f"✗ {result.message}")
                        messagebox.showerror("오류", result.message, parent=self.root)

                    self._refresh_drives()

                elif msg[0] == "se_done":
                    result: WipeResult = msg[1]
                    self.is_wiping = False
                    self.progress.stop()
                    self.progress.configure(mode="determinate")
                    self.btn_start.configure(state="normal")
                    self.btn_secure_erase.configure(state="normal")
                    self.btn_refresh.configure(state="normal")

                    if result.success:
                        self.progress["value"] = 100
                        self.lbl_progress.configure(text="Secure Erase 완료!")
                        self._log(f"✓ {result.message}")
                        messagebox.showinfo("완료", result.message, parent=self.root)
                    else:
                        self.progress["value"] = 0
                        self.lbl_progress.configure(text="Secure Erase 실패")
                        self._log(f"✗ {result.message}")
                        messagebox.showerror("오류", result.message, parent=self.root)

                    self._refresh_drives()

        except queue.Empty:
            pass

        self.root.after(100, self._poll_progress)

    # ── 취소 ─────────────────────────────────────────────

    def _on_cancel(self):
        if self.is_wiping:
            if messagebox.askyesno("취소 확인", "삭제를 취소하시겠습니까?\n(현재 진행 중인 쓰기 이후 중단됩니다)", parent=self.root):
                self.cancel_event.set()
                self._log("취소 요청됨... 현재 청크 완료 후 중단합니다.")

    # ── ATA Secure Erase ────────────────────────────────

    def _on_secure_erase(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("선택 필요", "디스크를 선택해주세요.", parent=self.root)
            return

        disk_num = int(selected[0])
        drive = next((d for d in self.drives if d.disk_number == disk_num), None)
        if not drive:
            messagebox.showerror("오류", "선택한 드라이브를 찾을 수 없습니다.", parent=self.root)
            return

        # 지원 여부 확인
        try:
            info = check_secure_erase(disk_num)
        except OSError as e:
            messagebox.showerror(
                "Secure Erase 불가",
                f"ATA pass-through을 지원하지 않는 디스크입니다.\n"
                f"(USB 연결 디스크는 대부분 미지원)\n\n{e}",
                parent=self.root,
            )
            return

        if not info.supported:
            messagebox.showinfo("미지원", "이 드라이브는 ATA Secure Erase를 지원하지 않습니다.", parent=self.root)
            return

        if info.frozen:
            messagebox.showwarning(
                "Frozen 상태",
                "드라이브가 'Frozen' 상태입니다.\n\n"
                "해제 방법:\n"
                "1. PC를 절전 모드로 전환 후 깨우기\n"
                "2. 또는 드라이브를 핫플러그 (분리 후 재연결)\n\n"
                "이후 다시 시도해주세요.",
                parent=self.root,
            )
            return

        if info.locked:
            messagebox.showerror("잠금 상태", "드라이브가 잠금 상태입니다.\n비밀번호를 해제해야 합니다.", parent=self.root)
            return

        if info.enabled:
            messagebox.showerror("보안 활성", "드라이브에 이미 보안 비밀번호가 설정되어 있습니다.", parent=self.root)
            return

        # Enhanced 가능 시 Enhanced 사용
        enhanced = info.enhanced_supported
        mode_str = "Enhanced" if enhanced else "Normal"
        time_est = info.enhanced_time_min if enhanced else info.normal_time_min
        time_str = f"약 {time_est}분" if time_est > 0 else "알 수 없음"

        if not messagebox.askyesno(
            "ATA Secure Erase",
            f"ATA Secure Erase ({mode_str}) 실행\n\n"
            f"드라이브: {drive.friendly_name}\n"
            f"용량: {drive.size_display}\n"
            f"예상 소요: {time_str}\n\n"
            "펌웨어 레벨에서 모든 데이터를 삭제합니다.\n"
            "SSD는 소프트웨어 삭제보다 더 확실합니다.\n\n"
            "계속하시겠습니까?",
            parent=self.root,
        ):
            return

        if not self._confirm_wipe_dialog(drive, mode_text=f"Secure Erase ({mode_str})"):
            return

        # 실행
        self.is_wiping = True
        self._wipe_start_time = time.time()
        self.cancel_event.clear()
        self.btn_start.configure(state="disabled")
        self.btn_secure_erase.configure(state="disabled")
        self.btn_cancel.configure(state="disabled")  # Secure Erase는 취소 불가
        self.btn_refresh.configure(state="disabled")
        self.progress.configure(mode="indeterminate")
        self.progress.start(10)

        self._log(f"Disk {disk_num}: ATA Secure Erase ({mode_str}) 시작")

        self.wipe_thread = threading.Thread(
            target=self._secure_erase_worker,
            args=(disk_num, enhanced),
            daemon=True,
        )
        self.wipe_thread.start()

    def _secure_erase_worker(self, disk_number: int, enhanced: bool):
        result = ata_secure_erase(disk_number, enhanced)
        self.progress_queue.put(("se_done", result))

    # ── 테마 ─────────────────────────────────────────────

    def _toggle_theme(self):
        """다크/라이트 모드 전환."""
        self._is_dark = not self._is_dark
        self._apply_theme()

    def _apply_theme(self):
        """현재 테마를 모든 위젯에 적용."""
        style = ttk.Style()
        if self._is_dark:
            style.theme_use("clam")
            c = _DARK
            style.configure(".", background=c["bg"], foreground=c["fg"],
                            fieldbackground=c["field"], bordercolor=c["border"])
            style.configure("TLabel", background=c["bg"], foreground=c["fg"])
            style.configure("TButton", background=c["button"], foreground=c["fg"])
            style.configure("TFrame", background=c["bg"])
            style.configure("TLabelframe", background=c["bg"], foreground=c["fg"])
            style.configure("TLabelframe.Label", background=c["bg"], foreground=c["fg"])
            style.configure("TRadiobutton", background=c["bg"], foreground=c["fg"],
                            indicatorcolor=c["field"])
            style.configure("TCheckbutton", background=c["bg"], foreground=c["fg"],
                            indicatorcolor=c["field"])
            style.configure("Treeview", background=c["field"], foreground=c["fg"],
                            fieldbackground=c["field"])
            style.configure("Treeview.Heading", background=c["tree_head"],
                            foreground=c["fg"])
            style.map("Treeview",
                       background=[("selected", c["select"])],
                       foreground=[("selected", "#ffffff")])
            style.map("TButton", background=[("active", "#505050")])
            style.configure("TProgressbar", background="#569cd6",
                            troughcolor=c["field"])

            self.root.configure(bg=c["bg"])
            self.log_text.configure(bg=c["field"], fg=c["fg"],
                                    insertbackground=c["fg"])
            self.tree.tag_configure("warn_letter", foreground="#ff6b6b")
            self._tooltip.bg = "#3d3d3d"
            self._tooltip.fg = "#d4d4d4"
            self.btn_theme.configure(text="라이트 모드")
        else:
            style.theme_use(self._default_theme)
            self.root.configure(bg="SystemButtonFace")
            self.log_text.configure(bg="white", fg="black", insertbackground="black")
            self.tree.tag_configure("warn_letter", foreground="red")
            self._tooltip.bg = "#ffffe0"
            self._tooltip.fg = "#000000"
            self.btn_theme.configure(text="다크 모드")

    # ── 디스크 검사 (헥스 뷰어) ────────────────────────────

    def _on_inspect(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("선택 필요", "검사할 디스크를 선택해주세요.", parent=self.root)
            return

        disk_num = int(selected[0])
        drive = next((d for d in self.drives if d.disk_number == disk_num), None)
        if not drive:
            messagebox.showerror("오류", "선택한 드라이브를 찾을 수 없습니다.", parent=self.root)
            return

        try:
            disk_size = get_disk_size(disk_num)
        except OSError as e:
            messagebox.showerror("오류", f"디스크 접근 실패:\n{e}", parent=self.root)
            return

        HexViewerDialog(self.root, disk_num, drive.friendly_name, disk_size)

    # ── 로그 ─────────────────────────────────────────────

    def _log(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")


# ── 헥스 뷰어 다이얼로그 ──────────────────────────────────


_BYTES_PER_LINE = 16
_LINES_PER_PAGE = 32  # 32줄 × 16바이트 = 512바이트 (1섹터)
_PAGE_SIZE = _BYTES_PER_LINE * _LINES_PER_PAGE  # 512

# 색상 태그
TAG_ZERO = "zero"      # 0x00 바이트 → 초록
TAG_FF = "ff"          # 0xFF 바이트 → 파랑
TAG_OTHER = "other"    # 그 외     → 빨강
TAG_OFFSET = "offset"  # 오프셋 컬럼
TAG_ASCII = "ascii"    # ASCII 컬럼


class HexViewerDialog:
    """디스크 raw 데이터를 헥스 덤프로 보여주는 다이얼로그."""

    def __init__(self, parent: tk.Tk, disk_number: int, disk_name: str, disk_size: int):
        self.disk_number = disk_number
        self.disk_size = disk_size
        self.current_offset = 0

        self.win = tk.Toplevel(parent)
        self.win.title(f"디스크 검사 — Disk {disk_number}: {disk_name}")
        self.win.minsize(780, 500)
        self.win.transient(parent)

        # 부모 창 중앙에 배치
        parent.update_idletasks()
        px, py = parent.winfo_x(), parent.winfo_y()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        x = px + (pw - 820) // 2
        y = py + (ph - 640) // 2
        self.win.geometry(f"820x640+{x}+{y}")

        self._build_ui(disk_name)
        self._read_and_display()

    def _build_ui(self, disk_name: str):
        self.win.columnconfigure(0, weight=1)
        self.win.rowconfigure(1, weight=1)

        # ── 상단: 정보 + 네비게이션 ──
        nav = ttk.Frame(self.win, padding=8)
        nav.grid(row=0, column=0, sticky="ew")
        nav.columnconfigure(3, weight=1)

        size_str = f"{self.disk_size / (1024**3):.1f} GB" if self.disk_size >= 1024**3 else f"{self.disk_size / (1024**2):.0f} MB"
        ttk.Label(nav, text=f"Disk {self.disk_number}: {disk_name}  ({size_str})", font=("", 10, "bold")).grid(row=0, column=0, columnspan=6, sticky="w", pady=(0, 6))

        ttk.Button(nav, text="<< 처음", command=self._go_start).grid(row=1, column=0, padx=2)
        ttk.Button(nav, text="< 이전", command=self._go_prev).grid(row=1, column=1, padx=2)
        ttk.Button(nav, text="다음 >", command=self._go_next).grid(row=1, column=2, padx=2)

        ttk.Label(nav, text="  오프셋 이동:").grid(row=1, column=4)
        self.offset_entry = ttk.Entry(nav, width=18)
        self.offset_entry.grid(row=1, column=5, padx=4)
        self.offset_entry.bind("<Return>", lambda e: self._go_to_offset())
        ttk.Button(nav, text="이동", command=self._go_to_offset).grid(row=1, column=6, padx=2)

        # 빠른 이동 버튼
        quick = ttk.Frame(nav)
        quick.grid(row=1, column=7, padx=(12, 0))
        ttk.Button(quick, text="25%", width=5, command=lambda: self._go_pct(0.25)).pack(side="left", padx=1)
        ttk.Button(quick, text="50%", width=5, command=lambda: self._go_pct(0.50)).pack(side="left", padx=1)
        ttk.Button(quick, text="75%", width=5, command=lambda: self._go_pct(0.75)).pack(side="left", padx=1)
        ttk.Button(quick, text="끝 >>", width=5, command=self._go_end).pack(side="left", padx=1)

        # ── 중앙: 헥스 덤프 텍스트 ──
        hex_frame = ttk.Frame(self.win)
        hex_frame.grid(row=1, column=0, padx=8, pady=4, sticky="nsew")
        hex_frame.columnconfigure(0, weight=1)
        hex_frame.rowconfigure(0, weight=1)

        self.hex_text = tk.Text(
            hex_frame, font=("Consolas", 10), state="disabled",
            wrap="none", bg="#1e1e1e", fg="#d4d4d4",
            selectbackground="#264f78", insertbackground="#d4d4d4",
        )
        self.hex_text.grid(row=0, column=0, sticky="nsew")

        sx = ttk.Scrollbar(hex_frame, orient="horizontal", command=self.hex_text.xview)
        sx.grid(row=1, column=0, sticky="ew")
        sy = ttk.Scrollbar(hex_frame, orient="vertical", command=self.hex_text.yview)
        sy.grid(row=0, column=1, sticky="ns")
        self.hex_text.configure(xscrollcommand=sx.set, yscrollcommand=sy.set)

        # 색상 태그 설정
        self.hex_text.tag_configure(TAG_ZERO, foreground="#4ec9b0")    # 초록 - 0x00
        self.hex_text.tag_configure(TAG_FF, foreground="#569cd6")      # 파랑 - 0xFF
        self.hex_text.tag_configure(TAG_OTHER, foreground="#f44747")   # 빨강 - 기타 데이터
        self.hex_text.tag_configure(TAG_OFFSET, foreground="#858585")  # 회색 - 오프셋
        self.hex_text.tag_configure(TAG_ASCII, foreground="#ce9178")   # 주황 - ASCII

        # ── 하단: 분석 결과 ──
        bottom = ttk.Frame(self.win, padding=8)
        bottom.grid(row=2, column=0, sticky="ew")
        bottom.columnconfigure(0, weight=1)

        self.lbl_status = ttk.Label(bottom, text="", font=("", 9))
        self.lbl_status.grid(row=0, column=0, sticky="w")

        self.lbl_analysis = ttk.Label(bottom, text="", font=("", 9, "bold"))
        self.lbl_analysis.grid(row=1, column=0, sticky="w", pady=(2, 0))

        # 범례
        legend = ttk.Frame(bottom)
        legend.grid(row=0, column=1, rowspan=2, sticky="e")
        tk.Label(legend, text="00", bg="#1e1e1e", fg="#4ec9b0", font=("Consolas", 9), padx=4).pack(side="left")
        ttk.Label(legend, text="= 0x00 (삭제됨)").pack(side="left", padx=(0, 10))
        tk.Label(legend, text="FF", bg="#1e1e1e", fg="#569cd6", font=("Consolas", 9), padx=4).pack(side="left")
        ttk.Label(legend, text="= 0xFF").pack(side="left", padx=(0, 10))
        tk.Label(legend, text="A3", bg="#1e1e1e", fg="#f44747", font=("Consolas", 9), padx=4).pack(side="left")
        ttk.Label(legend, text="= 기타 데이터").pack(side="left")

    def _read_and_display(self):
        """현재 오프셋에서 데이터를 읽고 헥스 덤프를 표시."""
        try:
            data = read_disk_sectors(self.disk_number, self.current_offset, _PAGE_SIZE)
        except OSError as e:
            self.hex_text.configure(state="normal")
            self.hex_text.delete("1.0", "end")
            self.hex_text.insert("end", f"읽기 오류: {e}")
            self.hex_text.configure(state="disabled")
            return

        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")

        # 분석 카운터
        count_zero = 0
        count_ff = 0
        count_other = 0

        for line_idx in range(_LINES_PER_PAGE):
            start = line_idx * _BYTES_PER_LINE
            if start >= len(data):
                break
            line_data = data[start: start + _BYTES_PER_LINE]
            abs_offset = self.current_offset + start

            # 오프셋
            offset_str = f"{abs_offset:012X}  "
            self.hex_text.insert("end", offset_str, TAG_OFFSET)

            # 헥스 바이트
            for i, byte in enumerate(line_data):
                hex_str = f"{byte:02X} "
                if byte == 0x00:
                    tag = TAG_ZERO
                    count_zero += 1
                elif byte == 0xFF:
                    tag = TAG_FF
                    count_ff += 1
                else:
                    tag = TAG_OTHER
                    count_other += 1
                self.hex_text.insert("end", hex_str, tag)

                # 8바이트마다 추가 공백
                if i == 7:
                    self.hex_text.insert("end", " ")

            # 부족한 바이트 패딩
            if len(line_data) < _BYTES_PER_LINE:
                missing = _BYTES_PER_LINE - len(line_data)
                self.hex_text.insert("end", "   " * missing)
                if len(line_data) <= 8:
                    self.hex_text.insert("end", " ")

            # ASCII 표현
            self.hex_text.insert("end", " |")
            ascii_chars = ""
            for byte in line_data:
                if 0x20 <= byte <= 0x7E:
                    ascii_chars += chr(byte)
                else:
                    ascii_chars += "."
            self.hex_text.insert("end", ascii_chars, TAG_ASCII)
            self.hex_text.insert("end", "|\n")

        self.hex_text.configure(state="disabled")

        # 상태 표시
        end_offset = min(self.current_offset + _PAGE_SIZE, self.disk_size)
        self.lbl_status.configure(
            text=f"오프셋: 0x{self.current_offset:012X} — 0x{end_offset:012X}  "
                 f"({self.current_offset:,} — {end_offset:,})"
        )

        # 분석 결과
        total = count_zero + count_ff + count_other
        if total == 0:
            self.lbl_analysis.configure(text="데이터 없음")
        elif count_other == 0 and count_ff == 0:
            self.lbl_analysis.configure(text=f"이 섹터: 전부 0x00 — 삭제 완료", foreground="green")
        elif count_other == 0 and count_zero == 0:
            self.lbl_analysis.configure(text=f"이 섹터: 전부 0xFF — 삭제 완료", foreground="blue")
        elif count_other == 0:
            self.lbl_analysis.configure(text=f"이 섹터: 0x00 + 0xFF만 존재 — 삭제 완료", foreground="green")
        else:
            pct = count_other / total * 100
            self.lbl_analysis.configure(
                text=f"이 섹터: 원본 데이터 {count_other}바이트 ({pct:.0f}%) 잔존 — 삭제 필요",
                foreground="red",
            )

    # ── 네비게이션 ──

    def _go_start(self):
        self.current_offset = 0
        self._read_and_display()

    def _go_prev(self):
        self.current_offset = max(0, self.current_offset - _PAGE_SIZE)
        self._read_and_display()

    def _go_next(self):
        new_offset = self.current_offset + _PAGE_SIZE
        if new_offset < self.disk_size:
            self.current_offset = new_offset
            self._read_and_display()

    def _go_end(self):
        self.current_offset = max(0, ((self.disk_size - _PAGE_SIZE) // 512) * 512)
        self._read_and_display()

    def _go_pct(self, pct: float):
        target = int(self.disk_size * pct)
        self.current_offset = (target // 512) * 512
        self._read_and_display()

    def _go_to_offset(self):
        text = self.offset_entry.get().strip()
        try:
            if text.startswith("0x") or text.startswith("0X"):
                offset = int(text, 16)
            else:
                offset = int(text)
        except ValueError:
            messagebox.showwarning("입력 오류", "유효한 숫자 또는 16진수(0x...)를 입력해주세요.", parent=self.win)
            return

        offset = max(0, min(offset, self.disk_size - _PAGE_SIZE))
        self.current_offset = (offset // 512) * 512
        self._read_and_display()


# ── Treeview 툴팁 ────────────────────────────────────────


class _TreeTooltip:
    """Treeview 행 위에 마우스를 올리면 나타나는 툴팁."""

    def __init__(self, widget: ttk.Treeview):
        self.widget = widget
        self.tip: tk.Toplevel | None = None
        self._current_item = ""
        self.bg = "#ffffe0"
        self.fg = "#000000"

    def show(self, text: str, event):
        item = self.widget.identify_row(event.y)
        if item == self._current_item and self.tip:
            return
        self.hide()
        self._current_item = item

        x = self.widget.winfo_rootx() + event.x + 20
        y = self.widget.winfo_rooty() + event.y + 15

        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")

        label = tk.Label(
            self.tip, text=text, justify="left",
            background=self.bg, foreground=self.fg,
            relief="solid", borderwidth=1,
            font=("Consolas", 9), padx=6, pady=4,
        )
        label.pack()

    def hide(self):
        if self.tip:
            self.tip.destroy()
            self.tip = None
            self._current_item = ""
