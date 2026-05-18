"""
CAPE Processing Model - Complete representation of CAPE section data
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AssociatedHashes(BaseModel):
    """Common hash structure for associated files."""

    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    sha3_384: Optional[str] = None


class YaraHit(BaseModel):
    """YARA rule match information."""

    name: str
    meta: Optional[Dict[str, Any]] = None
    strings: Optional[List[str]] = None
    addresses: Optional[Dict[str, Any]] = None


class FileInfo(BaseModel):
    """Complete file information from CAPE processing."""

    name: Optional[str] = None
    path: Optional[str] = None
    size: Optional[int] = None
    type: Optional[str] = None

    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    sha3_384: Optional[str] = None
    crc32: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    rh_hash: Optional[str] = None

    cape_type: Optional[str] = None
    cape_type_code: Optional[int] = None

    process_name: Optional[str] = None
    process_path: Optional[str] = None
    module_path: Optional[str] = None
    pid: Optional[Any] = None
    virtual_address: Optional[str] = None
    guest_paths: Optional[List[str]] = None

    yara: List[YaraHit] = Field(default_factory=list)
    cape_yara: List[YaraHit] = Field(default_factory=list)
    clamav: List[Any] = Field(default_factory=list)

    pe: Optional[Dict[str, Any]] = None

    selfextract: Optional[Dict[str, Any]] = None

    strings: Optional[List[str]] = None

    die: Optional[List[str]] = None

    data: Optional[Any] = None

    class Config:
        extra = "allow"


class CapeConfig(BaseModel):
    """Malware configuration extracted by CAPE."""

    family: Optional[str] = None
    config_data: Dict[str, Any] = Field(default_factory=dict)
    associated_config_hashes: List[AssociatedHashes] = Field(default_factory=list)
    associated_analysis_hashes: Optional[AssociatedHashes] = None

    class Config:
        extra = "allow"


class CAPEPayloadsAndConfigs(BaseModel):
    """CAPE payloads and configs."""

    payloads: List[FileInfo] = Field(default_factory=list)
    configs: List[CapeConfig] = Field(default_factory=list)


class CAPEProcessingResult(BaseModel):
    """Full CAPE processing result."""

    cape: CAPEPayloadsAndConfigs = Field(default_factory=CAPEPayloadsAndConfigs)

    dropped: List[FileInfo] = Field(default_factory=list)
    procdump: List[FileInfo] = Field(default_factory=list)
    package: List[FileInfo] = Field(default_factory=list)
    CAPE_path: List[FileInfo] = Field(default_factory=list)

    detections: List[Dict[str, Any]] = Field(default_factory=list)
    detections2pid: Dict[str, List[str]] = Field(default_factory=dict)

    other_categories: Dict[str, List[FileInfo]] = Field(default_factory=dict)
    pefiles: Dict[str, Any] = Field(default_factory=dict)
    additional: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"


class CAPEAISummary(BaseModel):
    """
    Compact but informative summary for AI consumption.
    Contains enough context for meaningful initial analysis.
    """

    detected_families: List[str] = Field(default_factory=list)

    total_payloads: int = Field(0)
    payload_types: Dict[str, int] = Field(default_factory=dict)

    injection_processes: List[Dict[str, Any]] = Field(default_factory=list)

    payload_examples: List[Dict[str, Any]] = Field(default_factory=list)

    total_configs: int = Field(0)
    has_valid_configs: bool = Field(False)

    c2_servers: List[str] = Field(default_factory=list)

    config_indicators: Dict[str, Any] = Field(default_factory=dict)

    process_family_mappings: Dict[str, List[str]] = Field(default_factory=dict)

    has_malware_config: bool = Field(False)
    has_dropped_files: bool = Field(False)
    primary_injection_method: Optional[str] = None
    quick_summary: str = ""

    def generate_summary(self) -> None:
        parts = []

        if self.detected_families:
            parts.append(f"Families: {', '.join(self.detected_families[:3])}")

        if self.c2_servers:
            c2_preview = ", ".join(self.c2_servers[:2])
            parts.append(f"C2: {c2_preview}")

        if self.total_payloads > 0:
            parts.append(f"Payloads: {self.total_payloads}")
            if self.injection_processes:
                proc_names = [p["process"] for p in self.injection_processes[:2]]
                parts.append(f"Injectors: {', '.join(proc_names)}")

        if self.has_valid_configs:
            parts.append("Config extracted")

        if self.process_family_mappings:
            parts.append(f"Infected PIDs: {len(self.process_family_mappings)}")

        self.quick_summary = " | ".join(parts) if parts else "No CAPE data extracted"

    class Config:
        json_schema_extra = {
            "example": {
                "detected_families": ["XWorm", "NanoCore"],
                "total_payloads": 15,
                "payload_types": {
                    "Shellcode": 8,
                    "PE DLL": 5,
                    "PE Executable": 2,
                },
                "injection_processes": [
                    {
                        "process": "powershell.exe",
                        "pid": 1304,
                        "payload_count": 8,
                    },
                    {
                        "process": "wermgr.exe",
                        "pid": 4852,
                        "payload_count": 5,
                    },
                ],
                "payload_examples": [
                    {
                        "cape_type": "Unpacked Shellcode",
                        "process": "powershell.exe",
                        "size": 281,
                    },
                    {
                        "cape_type": "Unpacked PE Image: 32-bit DLL",
                        "process": "d556f88c7c96cca6d869.exe",
                        "size": 71168,
                    },
                ],
                "total_configs": 2,
                "has_valid_configs": True,
                "c2_servers": ["203.202.232.149:2222", "88j.co.com:443"],
                "config_indicators": {
                    "Mutex": "4VeuKrW7wE9uXCl8",
                    "Group": "XWorm V7.1",
                    "Install": "true",
                },
                "process_family_mappings": {
                    "1764": ["XWorm"],
                    "4328": ["XWorm"],
                    "4852": ["NanoCore"],
                },
                "has_malware_config": True,
                "has_dropped_files": True,
                "primary_injection_method": "Shellcode injection",
                "quick_summary": "Families: XWorm, NanoCore | C2: 203.202.232.149:2222 | Payloads: 15 | Injectors: powershell.exe, wermgr.exe | Config extracted | Infected PIDs: 3",
            }
        }
