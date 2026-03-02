"""
USB Drive Secure Wiper 버전 정보 및 변경 이력.

버전 업 절차:
  1. 이 파일에서 __version__ 수정 + CHANGELOG 상단에 새 항목 추가
  2. CLAUDE.md "현재 버전" 업데이트
  3. 커밋: v{version}: {변경 요약}
"""

__version__ = "0.9.2"

# ---------------------------------------------------------------------------
# 변경 이력 (최신 → 과거 순)
# ---------------------------------------------------------------------------
# 각 항목 형식: (버전, 날짜, 변경 내용 리스트)
# 날짜는 YYYY-MM-DD
CHANGELOG: list[tuple[str, str, list[str]]] = [
    (
        "0.9.2",
        "2026-03-02",
        [
            "예상 남은 시간 표시 (진행률 바에 초/분/시간 단위)",
            "드라이브 상세 정보 툴팁 (모델명, 시리얼 번호, 미디어 타입)",
            "시스템 드라이브 문자(C:, D:) 포함 행 빨간색 경고 표시",
        ],
    ),
    (
        "0.9.1",
        "2026-03-02",
        [
            "SATA/ATA 디스크 지원 추가 (USB 외 HDD/SSD 삭제 가능)",
            "정밀 삭제 모드 추가 (7-pass DoD 5220.22-M 방식)",
            "팝업 창을 메인 창 중앙에 표시",
            "콘솔 창 없이 실행 (run.vbs로 변경)",
            "프로젝트 이름을 USB Secure Wiper (delete_usb)로 확정",
        ],
    ),
    (
        "0.9.0",
        "2026-03-02",
        [
            "초기 버전: USB 보안 삭제 GUI 앱",
            "PowerShell 기반 USB 드라이브 탐지 (BusType 필터링)",
            "ctypes Win32 API raw disk 덮어쓰기 (3-pass: zeros, ones, random)",
            "헥스 뷰어로 삭제 결과 시각 확인",
            "7중 안전장치 (시스템 드라이브 보호)",
            "UAC 자동 권한 상승",
        ],
    ),
]


def get_latest_changes() -> tuple[str, str, list[str]] | None:
    """최신 변경 항목 반환."""
    return CHANGELOG[0] if CHANGELOG else None


def format_changelog(count: int = 5) -> str:
    """최근 N개 버전의 변경 이력을 포맷팅."""
    lines = []
    for ver, date, changes in CHANGELOG[:count]:
        lines.append(f"v{ver} ({date})")
        for c in changes:
            lines.append(f"  - {c}")
        lines.append("")
    return "\n".join(lines)
