"""
Target Processing Model - Complete representation of Target section data
Includes target.file, detections, and detections2pid sections
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ============================================================
# Helper Models for target.file
# ============================================================

class GuestSigner(BaseModel):
    """Guest signature information (from pe.guest_signers)."""
    name: Optional[str] = None
    issued_to: Optional[str] = Field(None, alias="Issued to")
    issued_by: Optional[str] = Field(None, alias="Issued by")
    expires: Optional[str] = Field(None, alias="Expires")
    sha1_hash: Optional[str] = Field(None, alias="SHA1 hash")
    timestamp: Optional[str] = None


class DigitalSigner(BaseModel):
    """Digital signature information."""
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    sha1_fingerprint: Optional[str] = None
    sha256_fingerprint: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    subject_countryName: Optional[str] = None
    subject_organizationName: Optional[str] = None
    subject_organizationalUnitName: Optional[str] = None
    issuer_countryName: Optional[str] = None
    issuer_organizationName: Optional[str] = None


class GuestSignersContainer(BaseModel):
    """Container for guest signers from pe.guest_signers."""
    aux_sha1: Optional[str] = None
    aux_timestamp: Optional[str] = None
    aux_valid: bool = False
    aux_error: bool = False
    aux_error_desc: Optional[str] = None
    aux_signers: List[GuestSigner] = Field(default_factory=list)


class ImportFunction(BaseModel):
    """Individual imported function."""
    address: Optional[str] = None
    name: Optional[str] = None


class ImportedDLL(BaseModel):
    """Imported DLL information."""
    dll: str
    imports: List[ImportFunction] = Field(default_factory=list)


class DirectoryEntry(BaseModel):
    """PE directory entry."""
    name: str
    virtual_address: Optional[str] = None
    size: Optional[str] = None


class SectionEntry(BaseModel):
    """PE section entry."""
    name: str
    raw_address: Optional[str] = None
    virtual_address: Optional[str] = None
    virtual_size: Optional[str] = None
    size_of_data: Optional[str] = None
    characteristics: Optional[str] = None
    characteristics_raw: Optional[str] = None
    entropy: Optional[float] = None


class OverlayEntry(BaseModel):
    """PE overlay information."""
    offset: Optional[str] = None
    size: Optional[str] = None


class ResourceEntry(BaseModel):
    """PE resource entry."""
    name: Optional[str] = None
    offset: Optional[str] = None
    size: Optional[str] = None
    filetype: Optional[str] = None
    language: Optional[str] = None
    sublanguage: Optional[str] = None
    entropy: Optional[float] = None


class VersionInfoEntry(BaseModel):
    """Version info entry."""
    name: str
    value: Optional[str] = None


class PEInfo(BaseModel):
    """Complete PE information from target.file.pe."""
    # Guest signers
    guest_signers: Optional[GuestSignersContainer] = None
    
    # Digital signers
    digital_signers: List[DigitalSigner] = Field(default_factory=list)
    
    # Basic PE info
    imagebase: Optional[str] = None
    entrypoint: Optional[str] = None
    ep_bytes: Optional[str] = None
    reported_checksum: Optional[str] = None
    actual_checksum: Optional[str] = None
    osversion: Optional[str] = None
    pdbpath: Optional[str] = None
    peid_signatures: Optional[List[str]] = None
    imphash: Optional[str] = None
    timestamp: Optional[str] = None
    imported_dll_count: Optional[int] = None
    
    # Imports
    imports: Dict[str, ImportedDLL] = Field(default_factory=dict)
    
    # Exports
    exported_dll_name: Optional[str] = None
    exports: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Directories
    dirents: List[DirectoryEntry] = Field(default_factory=list)
    
    # Sections
    sections: List[SectionEntry] = Field(default_factory=list)
    
    # Overlay
    overlay: Optional[OverlayEntry] = None
    
    # Resources
    resources: List[ResourceEntry] = Field(default_factory=list)
    
    # Version info
    versioninfo: List[VersionInfoEntry] = Field(default_factory=list)
    
    # Icon info (without the actual base64 data for size reasons)
    icon: Optional[str] = None  # Will be truncated
    icon_hash: Optional[str] = None
    icon_fuzzy: Optional[str] = None
    icon_dhash: Optional[str] = None


class ExtractedFile(BaseModel):
    """Self-extracted file information."""
    name: Optional[str] = None
    path: Optional[str] = None
    guest_paths: Optional[List[str]] = None
    size: Optional[int] = None
    crc32: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    sha3_384: Optional[str] = None
    rh_hash: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    type: Optional[str] = None
    yara: List[Dict[str, Any]] = Field(default_factory=list)
    cape_yara: List[Dict[str, Any]] = Field(default_factory=list)
    clamav: List[Any] = Field(default_factory=list)
    die: List[str] = Field(default_factory=list)
    data: Optional[Any] = None


class SelfExtractEntry(BaseModel):
    """Self-extract entry (e.g., de4dot, overlay)."""
    extracted_files: List[ExtractedFile] = Field(default_factory=list)
    extracted_files_time: Optional[float] = None
    password: Optional[str] = None


class YaraMatch(BaseModel):
    """YARA rule match from target.file."""
    name: str
    meta: Optional[Dict[str, Any]] = None
    strings: Optional[List[str]] = None
    addresses: Optional[Dict[str, int]] = None


class TargetFile(BaseModel):
    """Complete target.file structure."""
    # Basic file info
    name: Optional[str] = None
    path: Optional[str] = None
    guest_paths: Optional[str] = None
    size: Optional[int] = None
    crc32: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    sha3_384: Optional[str] = None
    rh_hash: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    type: Optional[str] = None
    
    # CAPE classification
    cape_type: Optional[str] = None
    cape_type_code: Optional[int] = None
    
    # Detection results
    yara: List[YaraMatch] = Field(default_factory=list)
    cape_yara: List[YaraMatch] = Field(default_factory=list)
    clamav: List[Any] = Field(default_factory=list)
    
    # PE info (if applicable)
    pe: Optional[PEInfo] = None
    
    # Self-extract info
    selfextract: Dict[str, SelfExtractEntry] = Field(default_factory=dict)
    
    # Strings (limited preview in full model, but AI summary will handle)
    strings: Optional[List[str]] = None
    
    # Die (Detect It Easy) output
    die: Optional[List[str]] = None
    
    # Additional metadata
    data: Optional[Any] = None


class TargetSection(BaseModel):
    """Complete target section structure."""
    category: Optional[str] = None
    file: Optional[TargetFile] = None


# ============================================================
# Models for detections and detections2pid
# ============================================================

class DetectionDetail(BaseModel):
    """Individual detection detail (e.g., Yara hash)."""
    Yara: Optional[str] = None
    # Other possible fields in details
    extra: Dict[str, Any] = Field(default_factory=dict)


class Detection(BaseModel):
    """Detection entry from detections section."""
    family: str
    details: List[DetectionDetail] = Field(default_factory=list)


# ============================================================
# Complete Target Model
# ============================================================

class TargetModel(BaseModel):
    """
    Complete Target model containing:
    - target section (with full file details)
    - detections section
    - detections2pid section
    """
    
    # Target section
    target: Optional[TargetSection] = None
    
    # Detections section
    detections: List[Detection] = Field(default_factory=list)
    
    # detections2pid section
    detections2pid: Dict[str, List[str]] = Field(default_factory=dict)
    
    class Config:
        extra = "allow"


# ============================================================
# AI Summary Model (Compact for LLM)
# ============================================================

class TargetAISummary(BaseModel):
    """
    Compact summary of target data for AI consumption.
    Contains key indicators extracted from the full data.
    """
    
    # === File Identity ===
    sha256: Optional[str] = None
    md5: Optional[str] = None
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_type: Optional[str] = None
    
    # === CAPE Classification ===
    cape_type: Optional[str] = None
    cape_type_code: Optional[int] = None
    
    # === Detected Families ===
    detected_families: List[str] = Field(default_factory=list)
    
    # === Packing / Obfuscation (from die) ===
    die_info: List[str] = Field(default_factory=list)
    is_packed: bool = False  # High entropy sections
    
    # === Signing Info ===
    is_signed: bool = False
    signers: List[str] = Field(default_factory=list)  # Signer names
    signing_error: Optional[str] = None
    
    # === .NET Indicators ===
    is_dotnet: bool = False
    is_obfuscated: bool = False
    
    # === PE Indicators (from pe structure) ===
    imphash: Optional[str] = None
    compile_timestamp: Optional[str] = None
    entrypoint: Optional[str] = None
    pdb_path: Optional[str] = None
    
    # === High Entropy Sections (Packing Indicator) ===
    high_entropy_sections: List[str] = Field(default_factory=list)  # Section names with entropy > 7
    
    # === Version Info (For legitimacy detection) ===
    company_name: Optional[str] = None
    product_name: Optional[str] = None
    file_description: Optional[str] = None
    original_filename: Optional[str] = None
    legal_copyright: Optional[str] = None
    
    # === Self-Extraction (Dropper Behavior) ===
    has_self_extract: bool = False
    self_extract_method: Optional[str] = None
    extracted_files_count: int = 0
    extracted_file_types: List[str] = Field(default_factory=list)
    
    # === YARA Summary ===
    yara_rule_count: int = 0
    cape_yara_rule_count: int = 0
    critical_yara_rules: List[str] = Field(default_factory=list)  # Family names from YARA
    
    # === Process Mappings ===
    infected_processes: Dict[str, List[str]] = Field(default_factory=dict)
    
    # === Quick Assessment ===
    quick_summary: str = ""
    
    def generate_summary(self):
        """Generate the quick summary string."""
        parts = []
        
        if self.cape_type:
            clean_type = self.cape_type.replace("Payload:", "").strip()
            parts.append(f"Type: {clean_type[:40]}")
        
        if self.detected_families:
            parts.append(f"Family: {', '.join(self.detected_families[:2])}")
        
        if self.die_info:
            # Show first interesting die entry
            for die in self.die_info[:2]:
                if any(kw in die for kw in ["Eazfuscator", "Confuser", "UPX", "Themida"]):
                    parts.append(f"Packer: {die[:30]}")
                    break
        
        if self.is_signed:
            signer_name = self.signers[0][:20] if self.signers else "Yes"
            parts.append(f"Signed: {signer_name}")
        
        if self.has_self_extract:
            parts.append(f"Self-extract ({self.extracted_files_count} files)")
        
        if self.is_packed:
            parts.append("Packed")
        
        if self.infected_processes:
            parts.append(f"Infected PIDs: {len(self.infected_processes)}")
        
        if self.company_name and "Microsoft" in self.company_name:
            parts.append("Microsoft-signed")
        
        self.quick_summary = " | ".join(parts) if parts else "No target data"
    
    class Config:
        json_schema_extra = {
            "example": {
                "sha256": "d556f88c7c96cca6d86986e1fce426fed58bfa5966d59f51854ef6f5c65d1406",
                "md5": "52d0a799b8993fd52890bcbb63647709",
                "file_name": "d556f88c7c96cca6d869.exe",
                "file_size": 760320,
                "file_type": "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows",
                "cape_type": "XWorm Payload",
                "cape_type_code": 0,
                "detected_families": ["XWorm"],
                "die_info": ["Linker: Microsoft Linker", "Library: .NET Framework(v4.5, CLR v4.0.30319)"],
                "is_packed": False,
                "is_signed": False,
                "signers": [],
                "signing_error": None,
                "is_dotnet": True,
                "is_obfuscated": False,
                "imphash": "f34d5f2d4577ed6d9ceec516c1f5a744",
                "compile_timestamp": "2026-05-14 07:30:38",
                "entrypoint": "0x000baef2",
                "pdb_path": "OSoO.pdb",
                "high_entropy_sections": [],
                "company_name": None,
                "product_name": "AyInisAraci",
                "file_description": "AyInisAraci",
                "original_filename": "OSoO.exe",
                "legal_copyright": "Copyright Â© 2026",
                "has_self_extract": True,
                "self_extract_method": "de4dot",
                "extracted_files_count": 1,
                "extracted_file_types": ["PE32 executable"],
                "yara_rule_count": 0,
                "cape_yara_rule_count": 3,
                "critical_yara_rules": ["XWorm"],
                "infected_processes": {
                    "1764": ["XWorm"],
                    "4328": ["XWorm"]
                },
                "quick_summary": "Type: XWorm | Family: XWorm | Self-extract (1 files) | Infected PIDs: 2"
            }
        }


# ============================================================
# AI Summary Model for Detections (Compact)
# ============================================================

class DetectionsAISummary(BaseModel):
    """Compact summary of detections for AI."""
    families: List[str] = Field(default_factory=list)
    detection_count: int = 0
    process_mappings: Dict[str, List[str]] = Field(default_factory=dict)