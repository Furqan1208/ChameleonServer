from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class MemoryYaraHit(BaseModel):
    name: Optional[str] = None
    rule: Optional[str] = None
    addresses: Dict[str, int] = Field(default_factory=dict)
    memblocks: Dict[str, str] = Field(default_factory=dict)
    tags: Optional[List[str]] = Field(default_factory=list)
    meta: Optional[Dict[str, Any]] = Field(default_factory=dict)

    class Config:
        extra = "allow"


class MemoryChunk(BaseModel):
    start: Optional[str] = None
    end: Optional[str] = None
    offset: Optional[int] = None
    size: Optional[str] = None

    class Config:
        extra = "allow"


class MemoryMap(BaseModel):
    start: Optional[str] = None
    end: Optional[str] = None
    PE: Optional[bool] = None
    chunks: List[MemoryChunk] = Field(default_factory=list)

    class Config:
        extra = "allow"


class ProcessMemoryEntry(BaseModel):
    path: Optional[str] = None
    sha256: Optional[str] = None
    pid: Optional[int] = None
    name: Optional[str] = None
    proc_path: Optional[str] = None
    yara: List[Dict[str, Any]] = Field(default_factory=list)
    cape_yara: List[MemoryYaraHit] = Field(default_factory=list)
    address_space: List[MemoryMap] = Field(default_factory=list)
    strings_path: Optional[str] = None
    extracted_pe: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    class Config:
        extra = "allow"


class ProcMemoryProcessingResult(BaseModel):
    procmemory: List[ProcessMemoryEntry] = Field(default_factory=list)

    class Config:
        extra = "allow"
