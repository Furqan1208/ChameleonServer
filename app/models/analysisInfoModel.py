from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class MachineInfo(BaseModel):
    """Details about the analysis machine."""

    name: Optional[str] = None
    label: Optional[str] = None
    manager: Optional[str] = None
    started_on: Optional[str] = None
    shutdown_on: Optional[str] = None
    status: Optional[str] = None
    platform: Optional[str] = None
    ip: Optional[str] = None
    snapshot: Optional[str] = None
    # Any extra machine attributes returned by .to_dict()
    additional: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"


class InfoModel(BaseModel):
    """Top-level structure for the info section."""

    version: str = Field(..., description="CAPE/Cuckoo version")
    started: str = Field(..., description="Analysis start time")
    ended: str = Field(..., description="Analysis end time or 'none'")
    duration: int = Field(..., description="Duration in seconds (-1 if unknown)")
    id: int = Field(..., description="Task ID")
    category: str = Field(..., description="Category of the task")
    custom: Optional[str] = Field(None, description="Custom task string")
    machine: Optional[MachineInfo] = Field(None, description="Machine information")
    package: Optional[str] = Field(None, description="Used analysis package")
    timeout: bool = Field(..., description="True if analysis timed out")
    shrike_url: Optional[str] = Field(None, description="Shrike URL (if present)")
    shrike_refer: Optional[str] = Field(None, description="Shrike refer field")
    shrike_msg: Optional[str] = Field(None, description="Shrike message")
    shrike_sid: Optional[str] = Field(None, description="Shrike SID")
    parent_id: Optional[int] = Field(None, description="Parent task ID")
    tlp: Optional[str] = Field(None, description="TLP value")
    parent_sample: Optional[Any] = Field(
        None, description="Parent sample details (may be complex)"
    )
    options: Dict[str, Any] = Field(
        default_factory=dict, description="Parsed task options"
    )
    source_url: Optional[str] = Field(None, description="Source URL of the sample")
    route: Optional[str] = Field(None, description="Route used during analysis")
    user_id: Optional[int] = Field(None, description="User ID who submitted the task")
    CAPE_current_commit: str = Field(..., description="Current CAPE git commit hash")


class InfoSummary(BaseModel):
    """Compact summary of the info section for AI prompts."""

    sandbox_platform: Optional[str] = Field(None, description="Machine platform")
    analysis_type: Optional[str] = Field(None, description="Category of task")
    package_used: Optional[str] = Field(None, description="Package used for analysis")
    execution_completion_status: Optional[str] = Field(
        None, description="Completed/Timeout/Abnormal"
    )
    total_duration_seconds: Optional[int] = Field(None, description="Duration")
    timeout: Optional[bool] = Field(None, description="Timeout occurred")
    machine_status: Optional[str] = Field(None, description="Raw machine.status")


class InfoPayload(BaseModel):
    """Combined raw + summary payload returned by parser."""

    raw: InfoModel
    summary: InfoSummary

    class Config:
        extra = "allow"
