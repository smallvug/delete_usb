"""UAC 권한 상승 유틸리티."""

import ctypes
import sys


def is_admin() -> bool:
    """현재 프로세스가 관리자 권한인지 확인."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_as_admin():
    """UAC 프롬프트를 통해 관리자 권한으로 재실행.

    성공 시 현재 프로세스를 종료하고, 새 관리자 프로세스가 시작됨.
    사용자가 UAC를 거부하면 sys.exit(1).
    """
    script = sys.argv[0]
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        f'"{script}" {params}',
        None,
        1,  # SW_SHOWNORMAL
    )
    # ShellExecuteW returns > 32 on success
    if ret <= 32:
        sys.exit(1)
    sys.exit(0)
