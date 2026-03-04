# USB Secure Wiper

**폐기할 저장장치(USB, HDD, SSD)의 데이터를 복구 불가능하도록 완전 삭제하는 Windows GUI 프로그램**

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-0.9.4-blue)

---

## 개요

중고 판매, 폐기, 기증 전에 USB 플래시 드라이브, 외장 HDD, SATA SSD의 데이터를 물리적으로 덮어써서 복구 불가능하게 만드는 도구입니다. `\\.\PhysicalDriveN`에 직접 접근해 섹터 단위로 덮어쓰므로, 파일을 삭제하거나 포맷하는 것과는 차원이 다릅니다.

> **경고**: 이 프로그램으로 삭제한 데이터는 복구할 수 없습니다. 반드시 올바른 드라이브를 선택했는지 확인 후 실행하세요.

---

## 주요 기능

### 삭제 모드

| 모드 | 패스 수 | 패턴 | 설명 |
|------|---------|------|------|
| **빠른 삭제** | 1-pass | 0x00 | 단순 초기화. 빠르지만 포렌식 복구 가능성 있음 |
| **표준 삭제** | 3-pass | 0x00 → 0xFF → Random | 일반 보안 삭제에 충분 |
| **정밀 삭제** | 7-pass | DoD 5220.22-M | 0x00 → 0xFF → Random을 2회 반복 후 최종 Random |
| **ATA Secure Erase** | — | 펌웨어 레벨 | SSD 전용. 제조사 펌웨어가 직접 삭제 (가장 확실) |

### 안전 장치 (7중 보호)

- **Disk 0 항상 제외** — Windows 부팅 드라이브 보호
- **IsSystem / IsBoot 플래그 제외** — 시스템 디스크 자동 차단
- **BusType 필터** — USB, SATA, ATA만 허용 (NVMe, RAID, SAS 제외)
- **삭제 직전 재검증** — 실행 시점에 디스크가 여전히 대상인지 재확인
- **"WIPE" 타이핑 확인** — 오타 방지를 위한 필수 입력
- **2 TB 초과 경고** — 대용량 드라이브 선택 시 추가 확인
- **드라이브 문자 경고** — C:, D: 포함 행 빨간색 강조 표시

### UI 기능

- 드라이브 목록에서 모델명, 시리얼, 미디어 타입 툴팁 표시
- 실시간 진행률 바 + 예상 남은 시간 (초/분/시간 단위)
- **헥스 뷰어** — 삭제 전후 raw 데이터를 직접 눈으로 확인
  - 0x00 (초록), 0xFF (파랑), 기타 데이터 (빨강) 색상 구분
  - 오프셋 직접 이동 / 25%, 50%, 75% 퀵점프
- **삭제 후 자동 검증** — 랜덤 50개 섹터 샘플링, 정상 비율 표시
- 파티션 테이블 자동 제거 (PowerShell `Clear-Disk`)

---

## 요구 사항

- **Windows 10 / 11**
- **Python 3.11+**
- **관리자 권한** (물리 디스크 raw 접근 필요)
- 외부 라이브러리 없음 — 표준 라이브러리만 사용

---

## 설치 및 실행

```bash
# 저장소 클론
git clone https://github.com/<your-username>/delete_usb.git
cd delete_usb

# 실행 (UAC 프롬프트 → 관리자로 재실행)
python main.py
```

또는 `run.bat`을 더블클릭해 바로 실행합니다.

---

## 사용 방법

1. **드라이브 선택** — 목록에서 삭제할 디스크를 클릭
   - 마우스 호버 시 모델명·시리얼·파티션 정보 툴팁 표시
   - C:, D: 드라이브가 포함된 행은 빨간색으로 경고
2. **삭제 옵션 설정** — 빠른 / 표준 / 정밀 중 선택, 검증·파티션 제거 체크
3. **삭제 시작** 버튼 클릭 → 확인 다이얼로그에서 **`WIPE`** 입력
4. 진행률 바에서 실시간으로 진행 상황과 남은 시간 확인
5. 완료 후 **디스크 검사** 버튼으로 헥스 뷰어에서 결과 확인

### ATA Secure Erase (SSD 권장)

SATA SSD의 경우 소프트웨어 덮어쓰기보다 **ATA Secure Erase**가 더 확실합니다.
드라이브를 선택하고 **Secure Erase** 버튼을 클릭하세요.

> Frozen 상태인 경우: PC를 절전 모드로 전환 후 깨우거나, 드라이브를 핫플러그(분리 후 재연결)하면 해제됩니다.

---

## 파일 구조

```
delete_usb/
├── main.py          # 진입점: 관리자 권한 확인 + UAC 상승
├── admin_utils.py   # UAC 권한 상승 헬퍼
├── usb_detector.py  # PowerShell(Get-Disk) 기반 디스크 탐지
├── disk_wiper.py    # ctypes Win32 API 보안 삭제 엔진
├── gui_app.py       # tkinter GUI (드라이브 목록, 진행률, 헥스 뷰어)
├── version.py       # 버전 정보 + 변경 이력
└── run.bat          # 관리자 권한으로 바로 실행
```

### 기술 스택

- **Python 3.11+** 표준 라이브러리만 사용 (외부 의존성 0개)
- **tkinter** — GUI
- **ctypes** — Win32 API (`CreateFileW`, `WriteFile`, `DeviceIoControl`)
- **PowerShell** — 디스크 탐지 (`Get-Disk`, `Clear-Disk`)

---

## 주의사항

- **SSD wear leveling**: 소프트웨어 덮어쓰기는 일부 셀에 닿지 않을 수 있습니다. SSD는 ATA Secure Erase를 권장합니다.
- **NVMe SSD**: BusType 필터로 의도적으로 제외됩니다 (시스템 드라이브일 가능성이 높으므로).
- **USB 연결 드라이브**: USB-SATA 어댑터를 통한 연결은 ATA pass-through를 지원하지 않을 수 있어 Secure Erase가 불가능할 수 있습니다.

---

## 변경 이력

**v0.9.4** (2026-03-04)
- 다크 모드 제거 (기본 시스템 테마만 사용)

**v0.9.3** (2026-03-03)
- 삭제 후 자동 검증 (랜덤 50개 섹터 샘플링, 결과 요약 표시)
- ATA Secure Erase 지원 (SSD 펌웨어 레벨 삭제, Enhanced 모드)

**v0.9.2** (2026-03-02)
- 예상 남은 시간 표시 (진행률 바에 초/분/시간 단위)
- 드라이브 상세 정보 툴팁 (모델명, 시리얼 번호, 미디어 타입)
- 시스템 드라이브 문자(C:, D:) 포함 행 빨간색 경고 표시

**v0.9.1** (2026-03-02)
- SATA/ATA 디스크 지원 추가 (USB 외 HDD/SSD 삭제 가능)
- 정밀 삭제 모드 추가 (7-pass DoD 5220.22-M 방식)
- 팝업 창을 메인 창 중앙에 표시
- 콘솔 창 없이 실행

**v0.9.0** (2026-03-02)
- 초기 버전: USB 보안 삭제 GUI 앱
- PowerShell 기반 USB 드라이브 탐지 (BusType 필터링)
- ctypes Win32 API raw disk 덮어쓰기 (3-pass: zeros, ones, random)
- 헥스 뷰어로 삭제 결과 시각 확인
- 7중 안전장치 (시스템 드라이브 보호)
- UAC 자동 권한 상승

---

## 라이선스

MIT License
