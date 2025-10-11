from typing import List, Union

from pydantic import BaseModel, Field


class StatisticEntry(BaseModel):
    """Represents an individual entry with name and time."""

    name: str = Field(..., description="Name of the entry")
    time: Union[str, int, float] = Field(
        ..., description="Time associated with the entry"
    )


class Statistics(BaseModel):
    """Main statistics model containing processing, reporting, and signatures."""

    processing: List[StatisticEntry] = Field(
        default_factory=list, description="Processing statistics"
    )
    reporting: List[StatisticEntry] = Field(
        default_factory=list, description="Reporting statistics"
    )
    signatures: List[StatisticEntry] = Field(
        default_factory=list, description="Signatures statistics"
    )
