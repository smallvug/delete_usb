"""USB Secure Wiper - 진입점.

폐기할 저장장치(USB, HDD, SSD)를 보안 삭제하는 프로그램.
물리 디스크에 직접 접근해야 하므로 Windows 관리자 권한이 필수.

사용법:
    python main.py       # UAC 다이얼로그가 뜬 후 관리자로 재실행
    run.bat              # 더블클릭으로 바로 실행
"""

import logging
import sys
import tkinter as tk
from tkinter import messagebox

from admin_utils import is_admin, run_as_admin


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main():
    setup_logging()

    if not is_admin():
        root = tk.Tk()
        root.withdraw()
        result = messagebox.askokcancel(
            "관리자 권한 필요",
            "이 프로그램은 디스크에 직접 접근하기 위해\n"
            "관리자 권한이 필요합니다.\n\n"
            "확인을 누르면 Windows UAC 프롬프트가 표시됩니다.",
        )
        root.destroy()
        if result:
            run_as_admin()
        else:
            sys.exit(0)
    else:
        from gui_app import SecureWiperApp

        root = tk.Tk()
        SecureWiperApp(root)
        root.mainloop()


if __name__ == "__main__":
    main()
