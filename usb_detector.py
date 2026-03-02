"""PowerShell 기반 폐기 대상 디스크 탐지 (USB + SATA HDD)."""

import json
import logging
import subprocess
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 허용 BusType 목록: USB 플래시 + SATA HDD/SSD
# NVMe, RAID, SAS, 가상 디스크 등은 제외
ALLOWED_BUS_TYPES = {"USB", "SATA", "ATA"}

PS_SCRIPT = r"""
Get-Disk | Where-Object { $_.BusType -in @('USB', 'SATA', 'ATA') } | ForEach-Object {
    $disk = $_
    $parts = @()
    $partitions = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue
    if ($partitions) {
        $parts = $partitions | ForEach-Object {
            $vol = Get-Volume -Partition $_ -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                DriveLetter  = if ($_.DriveLetter) { [string]$_.DriveLetter } else { $null }
                FileSystem   = if ($vol) { $vol.FileSystemType } else { $null }
                Label        = if ($vol) { $vol.FileSystemLabel } else { $null }
                SizeGB       = [math]::Round($_.Size / 1GB, 2)
            }
        }
    }
    [PSCustomObject]@{
        Number       = $disk.Number
        FriendlyName = $disk.FriendlyName
        SerialNumber = $disk.SerialNumber
        Model        = $disk.Model
        MediaType    = $disk.MediaType
        BusType      = $disk.BusType
        Size         = $disk.Size
        IsSystem     = $disk.IsSystem
        IsBoot       = $disk.IsBoot
        Partitions   = @($parts)
    }
} | ConvertTo-Json -Depth 3
"""


@dataclass
class PartitionInfo:
    drive_letter: str | None
    filesystem: str | None
    label: str | None
    size_gb: float


@dataclass
class DriveInfo:
    disk_number: int
    friendly_name: str
    bus_type: str
    size_bytes: int
    is_system: bool
    is_boot: bool
    serial_number: str = ""
    model: str = ""
    media_type: str = ""
    partitions: list[PartitionInfo] = field(default_factory=list)

    @property
    def size_display(self) -> str:
        gb = self.size_bytes / (1024**3)
        if gb >= 1:
            return f"{gb:.1f} GB"
        mb = self.size_bytes / (1024**2)
        return f"{mb:.0f} MB"

    @property
    def physical_path(self) -> str:
        return rf"\\.\PhysicalDrive{self.disk_number}"

    @property
    def drive_letters(self) -> list[str]:
        return [p.drive_letter for p in self.partitions if p.drive_letter]


def detect_drives() -> list[DriveInfo]:
    """PowerShell로 폐기 대상 디스크를 탐지하여 반환.

    허용: USB, SATA, ATA (HDD/SSD)
    제외: NVMe(보통 시스템 드라이브), RAID, SAS, 가상 디스크

    안전 필터:
    - Disk 0 제외 (보통 시스템 드라이브)
    - IsSystem/IsBoot 플래그 드라이브 제외
    """
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", PS_SCRIPT],
        capture_output=True,
        text=True,
        timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    if result.returncode != 0:
        raise RuntimeError(f"PowerShell 오류: {result.stderr.strip()}")

    output = result.stdout.strip()
    if not output:
        return []

    data = json.loads(output)
    # 단일 결과는 dict, 복수는 list
    if isinstance(data, dict):
        data = [data]

    drives = []
    for disk in data:
        disk_num = disk["Number"]

        # 안전 필터: Disk 0 항상 제외
        if disk_num == 0:
            logger.warning("Disk 0 제외됨 (시스템 드라이브 보호)")
            continue

        # 안전 필터: IsSystem/IsBoot 제외
        if disk.get("IsSystem") or disk.get("IsBoot"):
            logger.warning(f"Disk {disk_num} 제외: IsSystem={disk.get('IsSystem')}, IsBoot={disk.get('IsBoot')}")
            continue

        partitions = []
        for part in disk.get("Partitions") or []:
            partitions.append(PartitionInfo(
                drive_letter=part.get("DriveLetter"),
                filesystem=part.get("FileSystem"),
                label=part.get("Label"),
                size_gb=part.get("SizeGB", 0),
            ))

        drives.append(DriveInfo(
            disk_number=disk_num,
            friendly_name=disk["FriendlyName"],
            bus_type=disk["BusType"],
            size_bytes=disk["Size"],
            is_system=disk.get("IsSystem", False),
            is_boot=disk.get("IsBoot", False),
            serial_number=disk.get("SerialNumber") or "",
            model=disk.get("Model") or "",
            media_type=disk.get("MediaType") or "",
            partitions=partitions,
        ))

    return drives


def refresh_drives() -> list[DriveInfo]:
    """detect_drives의 에러 안전 래퍼. 실패 시 빈 리스트 반환."""
    try:
        return detect_drives()
    except Exception as e:
        logger.error(f"디스크 탐지 실패: {e}")
        return []
