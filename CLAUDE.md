# USB Secure Wiper (delete_usb)

현재 버전: 0.9.5

폐기할 저장장치(USB, HDD, SSD)의 데이터를 복구 불가능하도록 보안 삭제하는 Windows GUI 프로그램.

## 기술 스택

- **Python 3.11+** (표준 라이브러리만 사용, 외부 의존성 0개)
- **tkinter** — GUI
- **ctypes** — Win32 API (CreateFileW, WriteFile, DeviceIoControl)
- **PowerShell** — 디스크 탐지 (Get-Disk)

## 디렉토리 구조

```
delete_usb/
├── CLAUDE.md          # 프로젝트 지침 (이 파일)
├── main.py            # 진입점: 관리자 권한 확인 + UAC 상승 + 앱 실행
├── admin_utils.py     # UAC 권한 상승 헬퍼
├── usb_detector.py    # PowerShell 기반 디스크 탐지 (USB + SATA)
├── disk_wiper.py      # ctypes Win32 API 보안 삭제 엔진
├── gui_app.py         # tkinter GUI (드라이브 목록, 진행률, 헥스 뷰어)
├── version.py         # 버전 정보 + 변경 이력
└── run.bat            # 관리자 권한으로 바로 실행하는 배치 파일
```

## 실행

```bash
python main.py       # UAC 다이얼로그 → 관리자 권한으로 재실행
# 또는
run.bat              # 더블클릭으로 바로 실행
```

## 핵심 동작

1. PowerShell `Get-Disk`으로 USB/SATA/ATA 디스크 탐지 (NVMe 제외)
2. 사용자가 드라이브 선택 → "WIPE" 타이핑 확인
3. `\\.\PhysicalDriveN`에 raw 쓰기로 전체 디스크 덮어쓰기
4. 삭제 후 헥스 뷰어로 결과 확인 가능

## 안전 장치

- BusType 필터: USB, SATA, ATA만 허용 (NVMe/RAID/SAS 제외)
- IsSystem/IsBoot 드라이브 제외
- Disk 0 항상 제외
- 삭제 직전 디스크 재검증
- "WIPE" 타이핑 확인 필수
- 2TB 초과 경고
- I/O 에러 시 즉시 중단

## 버전 관리

### 버전 정보 (Single Source of Truth)
- `version.py` — `__version__` 변수 + `CHANGELOG` 리스트

### 버전업 프로세스 ("버전업" 명령 시)

1. `version.py`에서 `__version__`을 0.0.1 올리고 + `CHANGELOG` 상단에 새 항목 추가
2. 이 CLAUDE.md의 "현재 버전" 업데이트
3. 커밋: `v{version}: {변경 요약}`
4. git push

> **CLAUDE.md 업데이트 규칙**: 이 파일은 버전업 시에만 업데이트한다. 사소한 변경에는 업데이트하지 않는다.

## 주의사항

- 관리자 권한 필수 (raw disk 접근에 필요)
- Windows 전용 (ctypes.windll, PowerShell Get-Disk 사용)
- SSD는 wear leveling으로 덮어쓰기가 불완전할 수 있음 — 제조사 Secure Erase가 더 확실
- 삭제된 데이터는 복구 불가능 — 실행 전 드라이브 확인 필수
