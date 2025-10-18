from typing import List

from pydantic import BaseModel, Field


class Ttp(BaseModel):
    signature: str
    ttps: List[str] = Field(default_factory=list)
    mbcs: List[str] = Field(default_factory=list)


class TtpsModel(BaseModel):
    Ttps: List[Ttp] = Field(default_factory=list)
