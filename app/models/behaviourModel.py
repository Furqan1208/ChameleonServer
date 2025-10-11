from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


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


class FileActivities(BaseModel):
    read_files: List[str] = Field(default_factory=list)
    write_files: List[str] = Field(default_factory=list)
    delete_files: List[str] = Field(default_factory=list)


class Process(BaseModel):
    process_id: int = Field(..., description="ID of the process")
    process_name: str = Field(..., description="Name of the process")
    parent_id: Optional[int] = Field(None, description="Parent process ID")
    module_path: Optional[str] = Field(None, description="Path to the module")
    first_seen: Optional[str] = Field(
        None, description="Timestamp when the process was first seen"
    )
    calls: List[CallEntry] = Field(
        default_factory=list, description="List of API calls"
    )
    threads: List[str] = Field(
        default_factory=list, description="Thread IDs for this process"
    )
    environ: Dict[str, Any] = Field(
        default_factory=dict, description="Environment variables / dictionary"
    )
    file_activities: FileActivities = Field(
        default_factory=FileActivities,
        description="Read / write / delete file activities",
    )


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


class Behaviour(BaseModel):
    processes: List[Process] = Field(
        default_factory=list, description="List of processes"
    )
    anomaly: List[AnomalyEntry] = Field(default_factory=list)
    processtree: List[TreeNode] = Field(default_factory=list)
    summary: Optional[SummaryModel] = None
    enhanced: List[EnhancedEvent] = Field(default_factory=list)
    encryptedbuffers: List[EncryptedBufferEntry] = Field(default_factory=list)


# class CapeReport(BaseModel):
#     # other top-level keys can go here, e.g. "info", "target", etc.
#     behavior: Behaviour = Field(..., description="Behavior section of the CAPE report")
