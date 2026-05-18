"""
Behavior Processing Model - Complete representation of Behavior section data
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


# ============================================================
# Helper Models - Minimal versions for AI
# ============================================================

class CallArgument(BaseModel):
    """API call argument - keep only essential fields for full model"""
    name: str
    value: Any
    pretty_value: Optional[str] = None


class CallEntry(BaseModel):
    """API call entry - KEPT ONLY IN FULL MODEL, EXCLUDED FROM AI SUMMARY"""
    timestamp: str
    thread_id: str
    caller: str
    parentcaller: str
    category: str
    api: str
    status: bool
    return_: Any = Field(..., alias="return")
    arguments: List[CallArgument]
    repeated: int
    pretty_return: Optional[str] = None
    
    model_config = {"populate_by_name": True}


class Environ(BaseModel):
    """Process environment - keep only CommandLine and UserName for AI"""
    UserName: Optional[str] = None
    ComputerName: Optional[str] = None
    WindowsPath: Optional[str] = None
    TempPath: Optional[str] = None
    CommandLine: Optional[str] = None
    RegisteredOwner: Optional[str] = None
    RegisteredOrganization: Optional[str] = None
    ProductName: Optional[str] = None
    SystemVolumeSerialNumber: Optional[str] = None
    SystemVolumeGUID: Optional[str] = None
    MachineGUID: Optional[str] = None
    MainExeBase: Optional[str] = None
    MainExeSize: Optional[str] = None
    Bitness: Optional[str] = None


class FileActivities(BaseModel):
    """File activities for a process"""
    read_files: List[str] = Field(default_factory=list)
    write_files: List[str] = Field(default_factory=list)
    delete_files: List[str] = Field(default_factory=list)


class Process(BaseModel):
    """Process information - calls EXCLUDED from AI summary"""
    process_id: int
    process_name: str
    parent_id: Optional[int] = None
    module_path: Optional[str] = None
    first_seen: Optional[str] = None
    # calls: KEPT IN FULL MODEL ONLY, EXCLUDED FROM AI
    calls: List[CallEntry] = Field(default_factory=list)
    # threads: EXCLUDED FROM AI
    threads: List[str] = Field(default_factory=list)
    environ: List[Environ] = Field(default_factory=list)
    file_activities: FileActivities = Field(default_factory=FileActivities)

    @field_validator("environ", mode="before")
    def normalize_environ(cls, v):
        if v is None:
            return []
        if isinstance(v, dict):
            return [Environ(**v)]
        if isinstance(v, list):
            normalized = []
            for item in v:
                if isinstance(item, dict):
                    normalized.append(Environ(**item))
                elif isinstance(item, Environ):
                    normalized.append(item)
            return normalized
        return []


class AnomalyEntry(BaseModel):
    """Anomaly detection entry"""
    name: str
    pid: int
    category: Optional[str] = None
    funcname: Optional[str] = None
    message: Optional[str] = None


class TreeNode(BaseModel):
    """Process tree node - threads EXCLUDED from AI"""
    name: str
    pid: int
    parent_id: Optional[int] = None
    module_path: Optional[str] = None
    children: List["TreeNode"] = Field(default_factory=list)
    threads: Optional[List[str]] = None  # EXCLUDED from AI
    environ: Optional[Dict[str, Any]] = None

    @field_validator("environ", mode="before")
    def normalize_tree_environ(cls, v):
        if isinstance(v, dict):
            return v
        return None


TreeNode.model_rebuild()


class SummaryModel(BaseModel):
    """Behavior summary - most fields KEPT, keys/read_keys aggregated"""
    files: List[str] = Field(default_factory=list)
    read_files: List[str] = Field(default_factory=list)
    write_files: List[str] = Field(default_factory=list)
    delete_files: List[str] = Field(default_factory=list)
    keys: List[str] = Field(default_factory=list)  # AGGREGATED in AI
    read_keys: List[str] = Field(default_factory=list)  # AGGREGATED in AI
    write_keys: List[str] = Field(default_factory=list)
    delete_keys: List[str] = Field(default_factory=list)
    executed_commands: List[str] = Field(default_factory=list)
    resolved_apis: List[str] = Field(default_factory=list)
    mutexes: List[str] = Field(default_factory=list)
    created_services: List[str] = Field(default_factory=list)
    started_services: List[str] = Field(default_factory=list)


class EnhancedEvent(BaseModel):
    """Enhanced events - EXCLUDED from AI"""
    event: str
    object: str
    timestamp: str
    eid: int
    data: Dict[str, Any]


class EncryptedBufferEntry(BaseModel):
    """Encrypted buffers - EXCLUDED from AI"""
    process_name: str
    pid: int
    api_call: str
    buffer: str
    buffer_size: Optional[int] = None
    crypt_key: Optional[str] = None


# ============================================================
# Call Statistics Models (for AI)
# ============================================================

class CallCategoryStats(BaseModel):
    """Statistics about API calls by category"""
    total: int = 0
    categories: Dict[str, int] = Field(default_factory=dict)
    unique_apis: List[str] = Field(default_factory=list)


class HighValueCall(BaseModel):
    """High-value API calls with context"""
    api: str
    count: int
    details: List[str] = Field(default_factory=list)  # e.g., file paths, registry keys


class ProcessCallStats(BaseModel):
    """API call statistics for a single process"""
    process_id: int
    process_name: str
    total_calls: int = 0
    category_stats: Dict[str, int] = Field(default_factory=dict)
    unique_apis: List[str] = Field(default_factory=list)
    high_value_calls: List[HighValueCall] = Field(default_factory=list)


# ============================================================
# Aggregated Summary Models (for AI)
# ============================================================

class KeysSummary(BaseModel):
    """Aggregated registry key summary"""
    total_count: int = 0
    unique_hives: List[str] = Field(default_factory=list)
    sample_keys: List[str] = Field(default_factory=list)


class BehaviorAISummary(BaseModel):
    """
    Compact AI summary for behavior section.
    Excludes: calls details, threads, enhanced, encryptedbuffers
    Aggregates: keys, read_keys
    """
    
    # === Process Overview ===
    total_processes: int = 0
    suspicious_processes: List[Dict[str, Any]] = Field(default_factory=list)
    
    # === Process Tree ===
    processtree: List[TreeNode] = Field(default_factory=list)
    
    # === API Call Statistics (replaces full calls) ===
    call_stats: List[ProcessCallStats] = Field(default_factory=list)
    total_api_calls: int = 0
    
    # === File Activity ===
    files_accessed: List[str] = Field(default_factory=list)
    files_written: List[str] = Field(default_factory=list)
    files_deleted: List[str] = Field(default_factory=list)
    
    # === Registry Activity ===
    keys_summary: Optional[KeysSummary] = None
    read_keys_summary: Optional[KeysSummary] = None
    write_keys: List[str] = Field(default_factory=list)
    delete_keys: List[str] = Field(default_factory=list)
    
    # === Command Execution ===
    executed_commands: List[str] = Field(default_factory=list)
    
    # === API Resolution ===
    resolved_apis: List[str] = Field(default_factory=list)
    
    # === Indicators ===
    mutexes: List[str] = Field(default_factory=list)
    created_services: List[str] = Field(default_factory=list)
    started_services: List[str] = Field(default_factory=list)
    
    # === Anomalies ===
    anomalies: List[AnomalyEntry] = Field(default_factory=list)
    
    # === Quick Assessment ===
    quick_summary: str = ""
    
    def generate_summary(self):
        """Generate quick summary string for AI"""
        parts = []
        
        if self.total_processes > 0:
            parts.append(f"Processes: {self.total_processes}")
        
        if self.suspicious_processes:
            proc_names = [p.get("name", "") for p in self.suspicious_processes[:3]]
            parts.append(f"Suspicious: {', '.join(proc_names)}")
        
        if self.files_written:
            parts.append(f"Files written: {len(self.files_written)}")
        
        if self.executed_commands:
            parts.append(f"Commands: {len(self.executed_commands)}")
        
        if self.keys_summary and self.keys_summary.total_count > 0:
            parts.append(f"Registry keys: {self.keys_summary.total_count}")
        
        if self.mutexes:
            parts.append(f"Mutexes: {len(self.mutexes)}")
        
        if self.created_services:
            parts.append("Services created")
        
        if self.anomalies:
            parts.append(f"Anomalies: {len(self.anomalies)}")
        
        if self.total_api_calls > 0:
            parts.append(f"API calls: {self.total_api_calls}")
        
        self.quick_summary = " | ".join(parts) if parts else "No behavior data"
    
    class Config:
        json_schema_extra = {
            "example": {
                "total_processes": 4,
                "suspicious_processes": [
                    {"pid": 4376, "name": "a8e9a8bebaf10e8238a7.exe", "cmdline": "...", "file_writes": 1}
                ],
                "processtree": [],
                "call_stats": [
                    {"process_id": 4376, "process_name": "malware.exe", "total_calls": 1247, "category_stats": {"filesystem": 342, "registry": 156}}
                ],
                "total_api_calls": 1247,
                "files_accessed": ["C:\\Windows\\System32\\kernel32.dll"],
                "files_written": ["C:\\Users\\cape\\AppData\\Roaming\\opera.exe"],
                "files_deleted": [],
                "keys_summary": {"total_count": 245, "unique_hives": ["HKLM", "HKCU"], "sample_keys": ["HKLM\\SOFTWARE\\Microsoft\\..."]},
                "read_keys_summary": {"total_count": 189, "unique_hives": ["HKLM", "HKCU"], "sample_keys": []},
                "write_keys": [],
                "delete_keys": [],
                "executed_commands": ["schtasks /create /tn \"Opera Startup\" /sc ONLOGON /tr \"...\""],
                "resolved_apis": ["ntdll.dll.RtlWow64GetCurrentMachine"],
                "mutexes": ["Local\\opera_a95ddb3d-5388-47e4-93b3-4bcb7a00d8d4"],
                "created_services": [],
                "started_services": [],
                "anomalies": [],
                "quick_summary": "Processes: 4 | Suspicious: a8e9a8bebaf10e8238a7.exe | Files written: 1 | Commands: 1 | Registry keys: 245 | Mutexes: 1 | API calls: 1247"
            }
        }


# ============================================================
# Full Behavior Model (Kept for reference)
# ============================================================

class BehaviorModel(BaseModel):
    """
    Complete behavior model - includes all raw data.
    For AI, use BehaviorAISummary instead.
    """
    processes: List[Process] = Field(default_factory=list)
    anomaly: List[AnomalyEntry] = Field(default_factory=list)
    processtree: List[TreeNode] = Field(default_factory=list)
    summary: Optional[SummaryModel] = None
    enhanced: List[EnhancedEvent] = Field(default_factory=list)
    encryptedbuffers: List[EncryptedBufferEntry] = Field(default_factory=list)
    
    class Config:
        extra = "allow"