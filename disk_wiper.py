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

# ATA pass-through (Secure Erase용)
IOCTL_ATA_PASS_THROUGH = 0x4D02C
ATA_FLAGS_DRDY_REQUIRED = 0x01
ATA_FLAGS_DATA_IN = 0x02
ATA_FLAGS_DATA_OUT = 0x04
ATA_CMD_IDENTIFY = 0xEC
ATA_CMD_SECURITY_SET_PASSWORD = 0xF1
ATA_CMD_SECURITY_ERASE_UNIT = 0xF4
ATA_CMD_SECURITY_DISABLE_PASSWORD = 0xF6

# 쓰기 단위: 1MB (512바이트 정렬 보장, USB 3.0 기준 ~10ms/청크)
CHUNK_SIZE = 1024 * 1024

kernel32 = ctypes.windll.kernel32


class _AtaPassThroughEx(ctypes.Structure):
    """ATA_PASS_THROUGH_EX 구조체 (Windows ntddscsi.h)."""
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("AtaFlags", ctypes.c_ushort),
        ("PathId", ctypes.c_ubyte),
        ("TargetId", ctypes.c_ubyte),
        ("Lun", ctypes.c_ubyte),
        ("ReservedAsUchar", ctypes.c_ubyte),
        ("DataTransferLength", ctypes.c_ulong),
        ("TimeOutValue", ctypes.c_ulong),
        ("ReservedAsUlong", ctypes.c_ulong),
        ("DataBufferOffset", ctypes.c_size_t),  # ULONG_PTR
        ("PreviousTaskFile", ctypes.c_ubyte * 8),
        ("CurrentTaskFile", ctypes.c_ubyte * 8),
    ]


class _AtaPassThroughBuf(ctypes.Structure):
    """ATA_PASS_THROUGH_EX + 512바이트 데이터 버퍼."""
    _fields_ = [
        ("apt", _AtaPassThroughEx),
        ("data", ctypes.c_ubyte * 512),
    ]


@dataclass
class WipeConfig:
    passes: list[str]  # ["zeros", "ones", "random"]
    verify: bool = True
    clean_disk: bool = True


@dataclass
class VerifyResult:
    """삭제 후 검증 결과."""
    total_samples: int
    clean_samples: int
    dirty_samples: int
    clean_pct: float


@dataclass
class SecureEraseInfo:
    """ATA Secure Erase 지원 상태."""
    supported: bool
    frozen: bool
    locked: bool
    enabled: bool       # 이미 비밀번호가 설정된 상태
    enhanced_supported: bool
    normal_time_min: int
    enhanced_time_min: int


@dataclass
class WipeResult:
    success: bool
    message: str
    cancelled: bool = False
    verify_result: VerifyResult | None = None


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


def verify_disk_wipe(disk_number: int, disk_size: int, num_samples: int = 50) -> VerifyResult:
    """삭제된 디스크를 랜덤 섹터 샘플링으로 검증.

    각 샘플(4KB)이 '삭제됨' 상태인지 확인:
    - 95% 이상 0x00 또는 0xFF → 정상 (패턴 삭제)
    - 고유 바이트 200종 이상 → 정상 (랜덤 삭제)
    - 그 외 → 원본 데이터 잔존 가능
    """
    import random

    SAMPLE_SIZE = 4096
    clean = 0
    dirty = 0

    path = rf"\\.\PhysicalDrive{disk_number}"
    handle = kernel32.CreateFileW(
        path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, 0, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise OSError(f"검증용 디스크 열기 실패 (error={ctypes.GetLastError()})")

    try:
        for _ in range(num_samples):
            offset = random.randrange(0, max(1, disk_size - SAMPLE_SIZE), 512)

            new_pos = ctypes.c_longlong(0)
            kernel32.SetFilePointerEx(
                handle, ctypes.c_longlong(offset), ctypes.byref(new_pos), 0,
            )

            buf = ctypes.create_string_buffer(SAMPLE_SIZE)
            read_count = ctypes.wintypes.DWORD(0)
            ok = kernel32.ReadFile(handle, buf, SAMPLE_SIZE, ctypes.byref(read_count), None)
            if not ok or read_count.value == 0:
                continue

            data = buf.raw[: read_count.value]
            zero_count = data.count(0)
            ff_count = data.count(0xFF)
            threshold = len(data) * 0.95

            if zero_count >= threshold or ff_count >= threshold:
                clean += 1
            elif len(set(data)) > 200:
                clean += 1
            else:
                dirty += 1

        total = clean + dirty
        return VerifyResult(
            total_samples=total,
            clean_samples=clean,
            dirty_samples=dirty,
            clean_pct=clean / total * 100 if total > 0 else 0,
        )
    finally:
        kernel32.CloseHandle(handle)


# ── ATA Secure Erase ─────────────────────────────────────────

_SE_PASSWORD = b"delete_usb"  # Secure Erase용 임시 비밀번호


def _ata_passthrough(handle: int, command: int, flags: int,
                     data_out: bytes | None = None, timeout: int = 10) -> bytes | None:
    """ATA pass-through 명령을 실행하고 결과를 반환."""
    buf = _AtaPassThroughBuf()
    struct_size = ctypes.sizeof(_AtaPassThroughEx)

    buf.apt.Length = struct_size
    buf.apt.AtaFlags = flags
    buf.apt.DataTransferLength = 512
    buf.apt.TimeOutValue = timeout
    buf.apt.DataBufferOffset = struct_size
    buf.apt.CurrentTaskFile[6] = command

    if data_out and (flags & ATA_FLAGS_DATA_OUT):
        for i, b in enumerate(data_out[:512]):
            buf.data[i] = b

    buf_size = ctypes.sizeof(buf)
    returned = ctypes.wintypes.DWORD(0)
    ok = kernel32.DeviceIoControl(
        handle, IOCTL_ATA_PASS_THROUGH,
        ctypes.byref(buf), buf_size,
        ctypes.byref(buf), buf_size,
        ctypes.byref(returned), None,
    )
    if not ok:
        err = ctypes.GetLastError()
        raise OSError(f"ATA pass-through 실패 (cmd=0x{command:02X}, error={err})")

    status = buf.apt.CurrentTaskFile[6]
    if status & 0x01:  # ERR 비트
        error_reg = buf.apt.CurrentTaskFile[0]
        raise OSError(
            f"ATA 명령 실패 (cmd=0x{command:02X}, "
            f"status=0x{status:02X}, error=0x{error_reg:02X})"
        )

    if flags & ATA_FLAGS_DATA_IN:
        return bytes(buf.data)
    return None


def _build_se_data(password: bytes, enhanced: bool = False) -> bytes:
    """SECURITY SET PASSWORD / SECURITY ERASE UNIT 명령용 512바이트 데이터."""
    data = bytearray(512)
    # Word 0 bit 1: 0=normal, 1=enhanced (erase 전용)
    if enhanced:
        data[0] = 0x02
    # Words 1-16 (offset 2~33): 비밀번호 (최대 32바이트)
    pwd = password[:32].ljust(32, b"\x00")
    data[2:34] = pwd
    return bytes(data)


def check_secure_erase(disk_number: int) -> SecureEraseInfo:
    """ATA IDENTIFY DEVICE로 Secure Erase 지원 여부를 확인."""
    path = rf"\\.\PhysicalDrive{disk_number}"
    handle = kernel32.CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, 0, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise OSError(f"디스크 열기 실패 (error={ctypes.GetLastError()})")

    try:
        identify = _ata_passthrough(
            handle, ATA_CMD_IDENTIFY,
            ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_IN,
        )

        # Word 128: Security 상태
        word128 = struct.unpack_from("<H", identify, 128 * 2)[0]
        # Word 89/90: 삭제 예상 시간
        word89 = struct.unpack_from("<H", identify, 89 * 2)[0]
        word90 = struct.unpack_from("<H", identify, 90 * 2)[0]

        def _parse_time(w: int) -> int:
            if w == 0 or w == 0xFFFF:
                return 0
            if w & 0x8000:  # bit 15 → 분 단위
                return w & 0x7FFF
            return (w & 0x7FFF) * 2  # 2분 단위

        return SecureEraseInfo(
            supported=bool(word128 & 0x0001),
            enabled=bool(word128 & 0x0002),
            locked=bool(word128 & 0x0004),
            frozen=bool(word128 & 0x0008),
            enhanced_supported=bool(word128 & 0x0020),
            normal_time_min=_parse_time(word89),
            enhanced_time_min=_parse_time(word90),
        )
    finally:
        kernel32.CloseHandle(handle)


def ata_secure_erase(disk_number: int, enhanced: bool = False) -> WipeResult:
    """ATA Secure Erase 실행.

    1. 임시 비밀번호 설정 (SECURITY SET PASSWORD)
    2. SECURITY ERASE UNIT 실행
    3. 성공 시 비밀번호 자동 해제
    4. 실패 시 비밀번호 수동 해제 시도
    """
    path = rf"\\.\PhysicalDrive{disk_number}"
    handle = kernel32.CreateFileW(
        path, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, 0, None,
    )
    if handle == INVALID_HANDLE_VALUE:
        raise OSError(f"디스크 열기 실패 (error={ctypes.GetLastError()})")

    password_set = False
    try:
        # 1. 임시 비밀번호 설정
        _ata_passthrough(
            handle, ATA_CMD_SECURITY_SET_PASSWORD,
            ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_OUT,
            data_out=_build_se_data(_SE_PASSWORD),
        )
        password_set = True
        logger.info("ATA Security: 임시 비밀번호 설정 완료")

        # 2. Secure Erase 실행 (최대 12시간 타임아웃)
        _ata_passthrough(
            handle, ATA_CMD_SECURITY_ERASE_UNIT,
            ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_OUT,
            data_out=_build_se_data(_SE_PASSWORD, enhanced=enhanced),
            timeout=43200,
        )
        logger.info("ATA Secure Erase 완료")

        mode = "Enhanced" if enhanced else "Normal"
        return WipeResult(
            True,
            f"ATA Secure Erase ({mode}) 완료.\n"
            "드라이브를 안전하게 폐기할 수 있습니다.",
        )

    except Exception as e:
        logger.error(f"ATA Secure Erase 실패: {e}")

        # 비밀번호 설정 후 erase 실패 → 비밀번호 해제 시도
        if password_set:
            try:
                _ata_passthrough(
                    handle, ATA_CMD_SECURITY_DISABLE_PASSWORD,
                    ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_OUT,
                    data_out=_build_se_data(_SE_PASSWORD),
                )
                logger.info("ATA Security: 비밀번호 해제 완료")
            except Exception as e2:
                logger.error(f"비밀번호 해제 실패: {e2}")
                return WipeResult(
                    False,
                    f"Secure Erase 실패 + 비밀번호 해제 실패!\n"
                    f"드라이브가 잠긴 상태일 수 있습니다.\n"
                    f"오류: {e}",
                )

        return WipeResult(False, f"ATA Secure Erase 실패: {e}")
