from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class StatisticEntry(BaseModel):
    """Represents one CAPE timing entry."""

    name: str = Field(..., description="Name of the entry")
    time: float = Field(..., description="Time associated with the entry")

    @field_validator("time", mode="before")
    @classmethod
    def _coerce_time(cls, value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0


class Statistics(BaseModel):
    """Raw CAPE statistics section."""

    processing: List[StatisticEntry] = Field(
        default_factory=list, description="Processing statistics"
    )
    reporting: List[StatisticEntry] = Field(
        default_factory=list, description="Reporting statistics"
    )
    signatures: List[StatisticEntry] = Field(
        default_factory=list, description="Signature timing statistics"
    )
    extra_sections: Dict[str, Any] = Field(
        default_factory=dict, description="Any extra CAPE statistics fields"
    )

    class Config:
        extra = "allow"


class SignatureSummary(BaseModel):
    """Compact summary for signature timings."""

    total_count: int = Field(..., description="Total signature entries")
    zero_time_count: int = Field(..., description="Signature entries with zero time")
    non_zero_count: int = Field(..., description="Signature entries with non-zero time")
    top_entries: List[StatisticEntry] = Field(
        default_factory=list, description="Top signature entries by time"
    )
    truncated_entries: int = Field(
        default=0, description="How many entries were omitted from the preview"
    )


class StatisticsSummary(BaseModel):
    """Compact statistics payload used by the LLM."""

    processing_summary: List[StatisticEntry] = Field(
        default_factory=list, description="Top processing timings"
    )
    reporting_summary: List[StatisticEntry] = Field(
        default_factory=list, description="Reporting timings"
    )
    signatures_summary: Optional[SignatureSummary] = Field(
        None, description="Compact signature timing summary"
    )
    total_processing_time: Optional[float] = Field(
        None, description="Total non-zero processing time"
    )
    max_processing_phase: Optional[str] = Field(
        None, description="Slowest processing phase"
    )
    max_processing_time: Optional[float] = Field(
        None, description="Slowest processing time"
    )
    zero_time_processing_count: Optional[int] = Field(
        None, description="Count of zero-time processing phases"
    )
    zero_time_signatures_count: Optional[int] = Field(
        None, description="Count of zero-time signature detections"
    )
    zero_time_weight: Optional[float] = Field(
        None, description="Derived weight for zero-time entries"
    )
    entry_counts: Dict[str, int] = Field(
        default_factory=dict, description="Counts for each statistics category"
    )
    extra_sections: Dict[str, Any] = Field(
        default_factory=dict, description="Any extra CAPE statistics fields"
    )

    class Config:
        extra = "allow"


class StatisticsPayload(BaseModel):
    """Raw and summarized CAPE statistics together."""

    raw: Statistics
    summary: StatisticsSummary

    class Config:
        extra = "allow"
