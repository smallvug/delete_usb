"""보안 삭제 엔진 — ctypes로 Win32 API를 직접 호출하여 물리 디스크를 덮어쓴다.

핵심 흐름:
  1. 볼륨 잠금/마운트 해제 (Windows가 디스크를 놓게 함)
  2. \\.\PhysicalDriveN 을 raw로 열기
  3. 1MB 청크 단위로 패턴(0x00, 0xFF, random)을 디스크 전체에 쓰기
  4. 선택적으로 마지막 패턴을 샘플링 검증
  5. 파티션 테이블 제거 (PowerShell Clear-Disk)

SSD 주의: wear leveling 때문에 덮어쓰기가 모든 셀에 닿지 않을 수 있음.
         SSD는 제조사 Secure Erase가 더 확실함.
"""

import ctypes
import ctypes.wintypes
import logging
import os
import struct
import subprocess
import threading
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ── Win32 API 상수 ──────────────────────────────────────────
# CreateFileW의 접근 권한 플래그
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value

# DeviceIoControl 제어 코드
IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C   # 디스크 총 바이트 크기 조회
FSCTL_LOCK_VOLUME = 0x00090018            # 볼륨 독점 잠금 (다른 프로세스 접근 차단)
FSCTL_UNLOCK_VOLUME = 0x0009001C          # 볼륨 잠금 해제
FSCTL_DISMOUNT_VOLUME = 0x00090020        # 볼륨 마운트 해제 (파일시스템 분리)

# 쓰기 단위: 1MB (512바이트 정렬 보장, USB 3.0 기준 ~10ms/청크)
CHUNK_SIZE = 1024 * 1024

kernel32 = ctypes.windll.kernel32


@dataclass
class WipeConfig:
    passes: list[str]  # ["zeros", "ones", "random"]
    verify: bool = True
    clean_disk: bool = True


@dataclass
class WipeResult:
    success: bool
    message: str
    cancelled: bool = False


# 진행률 콜백 시그니처:
# callback(pass_num, pass_name, bytes_done, total_bytes, overall_pct)
ProgressCallback = type(lambda: None)


def _format_size(size_bytes: int) -> str:
    gb = size_bytes / (1024**3)
    if gb >= 1:
        return f"{gb:.1f} GB"
    return f"{size_bytes / (1024**2):.0f} MB"


class DiskWiper:
    def __init__(self, disk_number: int, config: WipeConfig):
        self.disk_number = disk_number
        self.config = config
        self.physical_path = rf"\\.\PhysicalDrive{disk_number}"
        self._volume_handles: list[int] = []

    def wipe(
        self,
        progress_callback: ProgressCallback,
        cancel_event: threading.Event,
    ) -> WipeResult:
        """메인 삭제 메서드. 워커 스레드에서 실행.

        Args:
            progress_callback: (pass_num, pass_name, bytes_done, total_bytes, overall_pct) 콜백
            cancel_event: 취소 시그널용 Event
        """
        try:
            # 1. USB 드라이브 재검증
            if not self._validate_is_usb():
                return WipeResult(False, f"Disk {self.disk_number}은(는) USB 드라이브가 아니거나 더 이상 연결되어 있지 않습니다.")

            # 2. 볼륨 잠금 및 마운트 해제
            self._lock_volumes()

            # 3. 물리 디스크 열기
            handle = self._open_physical_disk()
            try:
                # 4. 디스크 크기 확인
                disk_size = self._get_disk_size(handle)
                logger.info(f"디스크 크기: {_format_size(disk_size)} ({disk_size:,} bytes)")

                total_passes = len(self.config.passes)

                # 5. 각 패스 실행
                for i, pass_name in enumerate(self.config.passes):
                    if cancel_event.is_set():
                        return WipeResult(False, "사용자가 삭제를 취소했습니다.", cancelled=True)

                    success = self._write_pass(
                        handle, disk_size, pass_name,
                        pass_num=i + 1, total_passes=total_passes,
                        callback=progress_callback,
                        cancel=cancel_event,
                    )
                    if not success:
                        if cancel_event.is_set():
                            return WipeResult(False, "사용자가 삭제를 취소했습니다.", cancelled=True)
                        return WipeResult(False, f"Pass {i + 1} ({pass_name}) 실패")

                # 6. 검증 (선택)
                if self.config.verify and not cancel_event.is_set():
                    last_pass = self.config.passes[-1]
                    if last_pass != "random":
                        verified = self._verify_pass(handle, disk_size, last_pass)
                        if not verified:
                            return WipeResult(False, "검증 실패: 데이터가 올바르게 쓰여지지 않았습니다.")

            finally:
                kernel32.CloseHandle(handle)

            # 7. 파티션 테이블 정리 (선택)
            if self.config.clean_disk and not cancel_event.is_set():
                self._clean_disk()

            return WipeResult(True, "보안 삭제가 완료되었습니다. 드라이브를 안전하게 폐기할 수 있습니다.")

        except Exception as e:
            logger.exception("삭제 중 오류 발생")
            return WipeResult(False, f"오류: {e}")

        finally:
            self._unlock_volumes()

    def _validate_is_usb(self) -> bool:
        """PowerShell로 디스크가 여전히 USB인지 재확인."""
        from usb_detector import detect_drives
        try:
            drives = detect_drives()
            return any(d.disk_number == self.disk_number for d in drives)
        except Exception as e:
            logger.error(f"USB 재검증 실패: {e}")
            return False

    def _lock_volumes(self):
        """디스크의 모든 볼륨을 잠금 및 마운트 해제."""
        from usb_detector import detect_drives
        drives = detect_drives()
        drive = next((d for d in drives if d.disk_number == self.disk_number), None)
        if not drive:
            return

        for letter in drive.drive_letters:
            vol_path = rf"\\.\{letter}:"
            h = kernel32.CreateFileW(
                vol_path,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if h == INVALID_HANDLE_VALUE:
                logger.warning(f"볼륨 {vol_path} 열기 실패")
                continue

            self._volume_handles.append(h)

            # 볼륨 잠금
            returned = ctypes.wintypes.DWORD(0)
            ok = kernel32.DeviceIoControl(
                h, FSCTL_LOCK_VOLUME,
                None, 0, None, 0,
                ctypes.byref(returned), None,
            )
            if not ok:
                logger.warning(f"볼륨 {vol_path} 잠금 실패 (error={ctypes.GetLastError()})")

            # 마운트 해제
            ok = kernel32.DeviceIoControl(
                h, FSCTL_DISMOUNT_VOLUME,
                None, 0, None, 0,
                ctypes.byref(returned), None,
            )
            if not ok:
                logger.warning(f"볼륨 {vol_path} 마운트 해제 실패")

            logger.info(f"볼륨 {vol_path} 잠금 및 마운트 해제 완료")

    def _unlock_volumes(self):
        """잠근 볼륨 핸들을 해제."""
        for h in self._volume_handles:
            try:
                returned = ctypes.wintypes.DWORD(0)
                kernel32.DeviceIoControl(
                    h, FSCTL_UNLOCK_VOLUME,
                    None, 0, None, 0,
                    ctypes.byref(returned), None,
                )
                kernel32.CloseHandle(h)
            except Exception:
                pass
        self._volume_handles.clear()

    def _open_physical_disk(self) -> int:
        """물리 디스크 핸들 열기."""
        handle = kernel32.CreateFileW(
            self.physical_path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.GetLastError()
            raise OSError(f"디스크 {self.physical_path} 열기 실패 (error={err}). 관리자 권한이 필요합니다.")
        return handle

    def _get_disk_size(self, handle: int) -> int:
        """IOCTL로 디스크 크기(바이트) 조회."""
        length_info = ctypes.c_ulonglong(0)
        returned = ctypes.wintypes.DWORD(0)
        ok = kernel32.DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None, 0,
            ctypes.byref(length_info), ctypes.sizeof(length_info),
            ctypes.byref(returned),
            None,
        )
        if not ok:
            raise OSError(f"디스크 크기 조회 실패 (error={ctypes.GetLastError()})")
        return length_info.value

    def _write_pass(
        self,
        handle: int,
        disk_size: int,
        pass_name: str,
        pass_num: int,
        total_passes: int,
        callback: ProgressCallback,
        cancel: threading.Event,
    ) -> bool:
        """하나의 패스 실행: 디스크 전체를 패턴으로 덮어쓰기."""
        # 파일 포인터를 시작으로 이동 (SetFilePointerEx)
        new_pos = ctypes.c_longlong(0)
        kernel32.SetFilePointerEx(handle, ctypes.c_longlong(0), ctypes.byref(new_pos), 0)

        # 패턴 생성
        if pass_name == "zeros":
            chunk = b"\x00" * CHUNK_SIZE
        elif pass_name == "ones":
            chunk = b"\xff" * CHUNK_SIZE
        elif pass_name == "random":
            chunk = None  # 매 청크마다 새로 생성
        else:
            raise ValueError(f"알 수 없는 패턴: {pass_name}")

        bytes_written_total = 0
        written = ctypes.wintypes.DWORD(0)

        while bytes_written_total < disk_size:
            if cancel.is_set():
                return False

            remaining = disk_size - bytes_written_total
            current_chunk_size = min(CHUNK_SIZE, remaining)

            # 512바이트 정렬
            aligned_size = ((current_chunk_size + 511) // 512) * 512

            if pass_name == "random":
                data = os.urandom(aligned_size)
            else:
                data = chunk[:aligned_size] if aligned_size <= CHUNK_SIZE else chunk + chunk[:aligned_size - CHUNK_SIZE]

            buf = ctypes.create_string_buffer(data)
            ok = kernel32.WriteFile(
                handle, buf, aligned_size,
                ctypes.byref(written), None,
            )
            if not ok:
                err = ctypes.GetLastError()
                # 디스크 끝에서 발생할 수 있는 에러 허용
                if bytes_written_total + aligned_size >= disk_size:
                    break
                logger.error(f"WriteFile 실패 at offset {bytes_written_total} (error={err})")
                return False

            bytes_written_total += written.value

            # 진행률 콜백
            overall_pct = ((pass_num - 1) / total_passes + (bytes_written_total / disk_size) / total_passes) * 100
            callback(pass_num, pass_name, bytes_written_total, disk_size, overall_pct)

        return True

    def _verify_pass(self, handle: int, disk_size: int, pass_name: str) -> bool:
        """마지막 패스 패턴 검증: 랜덤 위치 샘플링."""
        import random

        expected = b"\x00" if pass_name == "zeros" else b"\xff"
        sample_size = 512
        num_samples = min(16, max(1, disk_size // (1024 * 1024)))

        for _ in range(num_samples):
            offset = random.randrange(0, disk_size - sample_size, 512)
            new_pos = ctypes.c_longlong(0)
            kernel32.SetFilePointerEx(handle, ctypes.c_longlong(offset), ctypes.byref(new_pos), 0)

            buf = ctypes.create_string_buffer(sample_size)
            read = ctypes.wintypes.DWORD(0)
            ok = kernel32.ReadFile(handle, buf, sample_size, ctypes.byref(read), None)
            if not ok:
                return False

            if buf.raw[:read.value] != expected * read.value:
                return False

        return True

    def _clean_disk(self):
        """PowerShell로 파티션 테이블 정리."""
        try:
            cmd = f"Clear-Disk -Number {self.disk_number} -RemoveData -RemoveOEM -Confirm:$false"
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            logger.info(f"Disk {self.disk_number} 파티션 테이블 제거 완료")
        except Exception as e:
            logger.warning(f"파티션 테이블 제거 실패 (무시됨): {e}")


def read_disk_sectors(disk_number: int, offset: int, num_bytes: int = 512) -> bytes:
    """물리 디스크에서 raw 바이트를 읽어 반환.

    Args:
        disk_number: 디스크 번호 (예: 2)
        offset: 읽기 시작 위치 (바이트, 512 배수)
        num_bytes: 읽을 바이트 수 (512 배수, 기본 512)

    Returns:
        읽은 raw 바이트
    """
    # 512 정렬
    offset = (offset // 512) * 512
    num_bytes = max(512, ((num_bytes + 511) // 512) * 512)

    path = rf"\\.\PhysicalDrive{disk_number}"
    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise OSError(f"디스크 열기 실패 (error={ctypes.GetLastError()})")

    try:
        new_pos = ctypes.c_longlong(0)
        kernel32.SetFilePointerEx(handle, ctypes.c_longlong(offset), ctypes.byref(new_pos), 0)

        buf = ctypes.create_string_buffer(num_bytes)
        read_count = ctypes.wintypes.DWORD(0)
        ok = kernel32.ReadFile(handle, buf, num_bytes, ctypes.byref(read_count), None)
        if not ok:
            raise OSError(f"ReadFile 실패 (error={ctypes.GetLastError()})")

        return buf.raw[: read_count.value]
    finally:
        kernel32.CloseHandle(handle)


def get_disk_size(disk_number: int) -> int:
    """물리 디스크의 총 크기(바이트)를 반환."""
    path = rf"\\.\PhysicalDrive{disk_number}"
    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise OSError(f"디스크 열기 실패 (error={ctypes.GetLastError()})")

    try:
        length_info = ctypes.c_ulonglong(0)
        returned = ctypes.wintypes.DWORD(0)
        ok = kernel32.DeviceIoControl(
            handle,
            IOCTL_DISK_GET_LENGTH_INFO,
            None, 0,
            ctypes.byref(length_info), ctypes.sizeof(length_info),
            ctypes.byref(returned),
            None,
        )
        if not ok:
            raise OSError(f"디스크 크기 조회 실패 (error={ctypes.GetLastError()})")
        return length_info.value
    finally:
        kernel32.CloseHandle(handle)
