from typing import Any, List, Optional

from pydantic import BaseModel, Field


class SignatureDataEntry(BaseModel):
    type: str
    pid: Optional[int] = None
    cid: Optional[str] = None


class Signature(BaseModel):
    name: str
    description: Optional[str] = None
    categories: List[str] = Field(default_factory=list)
    severity: Optional[int] = None
    weight: Optional[int] = None
    confidence: Optional[int] = None
    references: List[str] = Field(default_factory=list)
    data: List[SignatureDataEntry] = Field(default_factory=list)
    families: List[str] = Field(default_factory=list)
    new_data: Optional[List[Any]] = None
    alert: Optional[bool] = False


class SignaturesModel(BaseModel):
    signatures: List[Signature] = Field(default_factory=list)
