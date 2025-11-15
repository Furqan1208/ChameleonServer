from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class CallArgument(BaseModel):
    name: str
    value: Any
    raw_value: Optional[Any] = None
    raw_value_string: Optional[str] = None
    pretty_value: Optional[str] = None


class CallEntry(BaseModel):
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


# ------------------------
# FIXED: Allow partial environ
# ------------------------
class Environ(BaseModel):
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
    read_files: List[str] = Field(default_factory=list)
    write_files: List[str] = Field(default_factory=list)
    delete_files: List[str] = Field(default_factory=list)


class Process(BaseModel):
    process_id: int
    process_name: str
    parent_id: Optional[int] = None
    module_path: Optional[str] = None
    first_seen: Optional[str] = None
    calls: List[CallEntry] = Field(default_factory=list)
    threads: List[str] = Field(default_factory=list)

    # FIXED: Normalize dict/list/None into List[Environ]
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
    name: str
    pid: int
    category: Optional[str] = None
    funcname: Optional[str] = None
    message: Optional[str] = None


class TreeNode(BaseModel):
    name: str
    pid: int
    parent_id: Optional[int] = None
    module_path: Optional[str] = None
    children: List["TreeNode"] = Field(default_factory=list)
    threads: Optional[List[str]] = None
    environ: Optional[Dict[str, Any]] = None

    @field_validator("environ", mode="before")
    def normalize_tree_environ(cls, v):
        if isinstance(v, dict):
            return v
        return None


TreeNode.model_rebuild()


class SummaryModel(BaseModel):
    files: List[str] = Field(default_factory=list)
    read_files: List[str] = Field(default_factory=list)
    write_files: List[str] = Field(default_factory=list)
    delete_files: List[str] = Field(default_factory=list)
    keys: List[str] = Field(default_factory=list)
    read_keys: List[str] = Field(default_factory=list)
    write_keys: List[str] = Field(default_factory=list)
    delete_keys: List[str] = Field(default_factory=list)
    executed_commands: List[str] = Field(default_factory=list)
    resolved_apis: List[str] = Field(default_factory=list)
    mutexes: List[str] = Field(default_factory=list)
    created_services: List[str] = Field(default_factory=list)
    started_services: List[str] = Field(default_factory=list)


class EnhancedEvent(BaseModel):
    event: str
    object: str
    timestamp: str
    eid: int
    data: Dict[str, Any]


class EncryptedBufferEntry(BaseModel):
    process_name: str
    pid: int
    api_call: str
    buffer: str
    buffer_size: Optional[int] = None
    crypt_key: Optional[str] = None


class Behavior(BaseModel):
    processes: List[Process] = Field(default_factory=list)
    anomaly: List[AnomalyEntry] = Field(default_factory=list)
    processtree: List[TreeNode] = Field(default_factory=list)
    summary: Optional[SummaryModel] = None
    enhanced: List[EnhancedEvent] = Field(default_factory=list)
    encryptedbuffers: List[EncryptedBufferEntry] = Field(default_factory=list)
