from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ============================================================
# Helper Models (Shared across all three sections)
# ============================================================

class YaraHit(BaseModel):
    """YARA rule match - simplified for AI consumption."""
    name: str
    meta: Optional[Dict[str, Any]] = None
    addresses: Optional[Dict[str, Any]] = None
    strings: Optional[List[str]] = None


class MemoryYaraHit(BaseModel):
    """YARA hit specific to memory dumps (with memblocks)."""
    name: Optional[str] = None
    rule: Optional[str] = None
    addresses: Dict[str, int] = Field(default_factory=dict)
    memblocks: Dict[str, str] = Field(default_factory=dict)
    tags: Optional[List[str]] = Field(default_factory=list)
    meta: Optional[Dict[str, Any]] = Field(default_factory=dict)

    class Config:
        extra = "allow"


class MemoryChunk(BaseModel):
    """Individual memory region chunk."""
    start: Optional[str] = None
    end: Optional[str] = None
    offset: Optional[int] = None
    size: Optional[str] = None
    prot: Optional[str] = None
    state: Optional[int] = None
    type: Optional[int] = None
    PE: Optional[bool] = None

    class Config:
        extra = "allow"


class MemoryMap(BaseModel):
    """Memory region map - KEEP SUMMARY ONLY, not full chunks."""
    start: Optional[str] = None
    end: Optional[str] = None
    size: Optional[str] = None
    prot: Optional[str] = None
    PE: Optional[bool] = None
    chunk_count: int = 0  # Count of sub-chunks instead of listing them
    # EXCLUDED: full chunks list (too large, low value)

    class Config:
        extra = "allow"


# ============================================================
# Models for Extracted Files (Procdump & Dropped)
# ============================================================

class ExtractedFile(BaseModel):
    """Common structure for procdump and dropped files."""
    
    # Identification
    name: Optional[str] = None
    path: Optional[str] = None
    size: Optional[int] = None
    type: Optional[str] = None
    
    # Hashes
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    sha3_384: Optional[str] = None
    crc32: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    
    # CAPE classification
    cape_type: Optional[str] = None
    cape_type_code: Optional[int] = None
    
    # Process information (where this file came from)
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    pid: Optional[int] = None
    virtual_address: Optional[str] = None
    guest_paths: Optional[List[str]] = None
    
    # Detection results (keep rule names only)
    yara_rules: List[str] = Field(default_factory=list)  # Simplified
    cape_yara_rules: List[str] = Field(default_factory=list)
    clamav_hits: List[str] = Field(default_factory=list)
    
    # Die output (packer detection)
    die: List[str] = Field(default_factory=list)
    
    # Self-extraction info
    selfextract_method: Optional[str] = None
    extracted_files_count: int = 0
    
    # Data (only for small files, e.g., < 10KB)
    data: Optional[str] = None
    
    class Config:
        extra = "allow"


class MemoryExtractedPE(BaseModel):
    """PE file extracted from memory dump."""
    name: Optional[str] = None
    path: Optional[str] = None
    size: Optional[int] = None
    type: Optional[str] = None
    sha256: Optional[str] = None
    md5: Optional[str] = None
    yara_rules: List[str] = Field(default_factory=list)
    cape_yara_rules: List[str] = Field(default_factory=list)
    die: List[str] = Field(default_factory=list)

    class Config:
        extra = "allow"


class ProcessMemoryEntry(BaseModel):
    """Single process memory dump (with address_space summarized)."""
    
    # Basic info
    path: Optional[str] = None
    sha256: Optional[str] = None
    pid: Optional[int] = None
    name: Optional[str] = None
    proc_path: Optional[str] = None
    
    # YARA hits (keep full for memory)
    yara: List[YaraHit] = Field(default_factory=list)
    cape_yara: List[MemoryYaraHit] = Field(default_factory=list)
    
    # Memory map SUMMARY (not full address_space)
    memory_regions: List[MemoryMap] = Field(default_factory=list)
    total_regions: int = 0
    executable_regions: int = 0
    writable_regions: int = 0
    
    # Strings path (reference only)
    strings_path: Optional[str] = None
    
    # Extracted PEs from this memory dump
    extracted_pe: List[MemoryExtractedPE] = Field(default_factory=list)
    
    # Quick assessment (computed)
    has_shellcode: bool = False
    has_injected_code: bool = False
    
    class Config:
        extra = "allow"


# ============================================================
# Top-Level Models for Each Section
# ============================================================

class ProcdumpData(BaseModel):
    """Complete procdump section."""
    files: List[ExtractedFile] = Field(default_factory=list)
    
    # Aggregated stats
    total_files: int = 0
    total_pe_files: int = 0
    file_types: Dict[str, int] = Field(default_factory=dict)


class DroppedData(BaseModel):
    """Complete dropped section."""
    files: List[ExtractedFile] = Field(default_factory=list)
    
    # Aggregated stats
    total_files: int = 0
    file_types: Dict[str, int] = Field(default_factory=dict)
    suspicious_paths: List[str] = Field(default_factory=list)


class ProcmemoryData(BaseModel):
    """Complete procmemory section."""
    memory_dumps: List[ProcessMemoryEntry] = Field(default_factory=list)
    
    # Aggregated stats
    total_dumps: int = 0
    dumps_with_yara: int = 0
    dumps_with_shellcode: int = 0
    total_extracted_pe: int = 0


# ============================================================
# Complete Unified Model
# ============================================================

class ProcessArtifactsResult(BaseModel):
    """
    Complete result for procdump, dropped, and procmemory sections.
    Output: { "full": {...}, "ai_summary": {...} }
    """
    
    # The three sections
    procdump: ProcdumpData = Field(default_factory=ProcdumpData)
    dropped: DroppedData = Field(default_factory=DroppedData)
    procmemory: ProcmemoryData = Field(default_factory=ProcmemoryData)
    
    class Config:
        extra = "allow"


# ============================================================
# AI Summary Model (Compact for LLM)
# ============================================================

class ProcessArtifactsAISummary(BaseModel):
    """
    Ultra-compact summary for AI consumption.
    Contains only what matters for malware analysis.
    """
    
    # === Overall Stats ===
    total_procdump_files: int = 0
    total_dropped_files: int = 0
    total_memory_dumps: int = 0
    
    # === Procdump Highlights ===
    procdump_pe_count: int = 0
    procdump_malware_families: List[str] = Field(default_factory=list)
    procdump_processes: List[str] = Field(default_factory=list)
    
    # === Dropped Highlights ===
    dropped_notable_files: List[Dict[str, str]] = Field(default_factory=list)  # name + path
    
    # === Memory Highlights ===
    memory_dumps_with_yara: int = 0
    memory_dump_processes: List[str] = Field(default_factory=list)
    memory_shellcode_detected: bool = False
    memory_injection_detected: bool = False
    extracted_pe_from_memory_count: int = 0
    
    # === YARA Summary ===
    total_yara_hits: int = 0
    critical_malware_rules: List[str] = Field(default_factory=list)
    
    # === Quick Assessment ===
    quick_summary: str = ""
    
    def generate_summary(self):
        """Generate quick summary string."""
        parts = []
        
        if self.procdump_pe_count > 0:
            parts.append(f"Procdump: {self.procdump_pe_count} PEs")
            if self.procdump_malware_families:
                parts.append(f"Families: {', '.join(self.procdump_malware_families[:2])}")
        
        if self.total_dropped_files > 0:
            parts.append(f"Dropped: {self.total_dropped_files} files")
        
        if self.memory_dumps_with_yara > 0:
            parts.append(f"Memory: {self.memory_dumps_with_yara} with YARA")
        
        if self.memory_shellcode_detected:
            parts.append("Shellcode in memory")
        
        if self.memory_injection_detected:
            parts.append("Code injection")
        
        if self.extracted_pe_from_memory_count > 0:
            parts.append(f"Extracted from memory: {self.extracted_pe_from_memory_count}")
        
        self.quick_summary = " | ".join(parts) if parts else "No process artifacts"
    
    class Config:
        json_schema_extra = {
            "example": {
                "total_procdump_files": 1,
                "total_dropped_files": 4,
                "total_memory_dumps": 5,
                "procdump_pe_count": 1,
                "procdump_malware_families": ["XWorm"],
                "procdump_processes": ["d556f88c7c96cca6d869.exe"],
                "dropped_notable_files": [
                    {"name": "report.wer", "path": "c:\\programdata\\microsoft\\windows\\wer\\..."}
                ],
                "memory_dumps_with_yara": 2,
                "memory_dump_processes": ["039cc3d021f34d2b7844.exe", "wermgr.exe"],
                "memory_shellcode_detected": True,
                "memory_injection_detected": True,
                "extracted_pe_from_memory_count": 4,
                "total_yara_hits": 6,
                "critical_malware_rules": ["XWorm", "dcrat_kingrat"],
                "quick_summary": "Procdump: 1 PEs | Families: XWorm | Memory: 2 with YARA | Shellcode in memory | Extracted from memory: 4"
            }
        }


# ============================================================
# Legacy/Compatibility Type
# ============================================================

class ProcMemoryProcessingResult(BaseModel):
    """Legacy compatibility wrapper."""
    procmemory: List[ProcessMemoryEntry] = Field(default_factory=list)
    
    class Config:
        extra = "allow"