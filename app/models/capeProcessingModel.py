from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# 🧱 Helper Models
# ---------------------------------------------------------------------------


class AssociatedHashes(BaseModel):
    """Common hash structure (MD5/SHA1/SHA256/SHA512/SHA3-384)."""

    md5: Optional[str] = ""
    sha1: Optional[str] = ""
    sha256: Optional[str] = ""
    sha512: Optional[str] = ""
    sha3_384: Optional[str] = ""


class SelfExtractedFile(BaseModel):
    """Structure for files extracted via self-extraction routines."""

    path: Optional[str] = None
    sha256: Optional[str] = None
    data: Optional[Any] = None
    cape_yara: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    extracted_files: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    class Config:
        extra = "allow"


class FileInfo(BaseModel):
    """
    Represents a file processed during CAPE analysis.
    This mirrors many attributes returned by `File.get_all()` and enriched by
    CAPE processing (metadata, yara hits, flare capa, extracted info, etc.).
    """

    name: Optional[str] = None
    path: Optional[str] = None
    size: Optional[int] = None
    type: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    sha3_384: Optional[str] = None

    cape_type: Optional[str] = None
    cape_type_code: Optional[int] = None
    cape_yara: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    selfextract: Optional[Dict[str, Any]] = Field(default_factory=dict)

    process_path: Optional[str] = None
    process_name: Optional[str] = None
    module_path: Optional[str] = None
    pid: Optional[Any] = None  # can be str, int, or csv string
    pids: Optional[List[Any]] = Field(default_factory=list)
    ppids: Optional[List[Any]] = Field(default_factory=list)
    target_path: Optional[str] = None
    target_process: Optional[str] = None
    target_pid: Optional[Any] = None
    virtual_address: Optional[str] = None

    guest_paths: Optional[List[str]] = Field(default_factory=list)
    data: Optional[Any] = None

    clamav: Optional[Any] = None
    flare_capa: Optional[Any] = None

    metadata: Optional[str] = None

    additional: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"


class CapeConfig(BaseModel):
    """
    Represents one configuration parsed by CAPE config parsers.
    Usually shaped like: {"<malware_family>": {...}, "_associated_config_hashes": [...]}
    """

    _associated_config_hashes: Optional[List[Dict[str, str]]] = Field(
        default_factory=list
    )
    _associated_analysis_hashes: Optional[Dict[str, Optional[str]]] = Field(
        default_factory=dict
    )
    config_data: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"


class CAPEPayloadsAndConfigs(BaseModel):
    """
    This mirrors the `self.cape` dict produced by CAPE.run():
    {
        "payloads": [<FileInfo>],
        "configs": [<CapeConfig or dict>]
    }
    """

    payloads: List[FileInfo] = Field(default_factory=list)
    configs: List[Dict[str, Any]] = Field(default_factory=list)

    class Config:
        extra = "allow"


class CAPEProcessingResult(BaseModel):
    """
    Full CAPE processing output, reflecting both `self.cape` and other
    categories added during processing (dropped, procdump, detections, etc.)
    """

    cape: CAPEPayloadsAndConfigs = Field(default_factory=CAPEPayloadsAndConfigs)

    # Common lists populated during process_file()
    dropped: List[FileInfo] = Field(default_factory=list)
    procdump: List[FileInfo] = Field(default_factory=list)
    package: List[FileInfo] = Field(default_factory=list)
    CAPE_path: List[FileInfo] = Field(default_factory=list)

    other_categories: Dict[str, List[FileInfo]] = Field(default_factory=dict)

    target: Optional[Dict[str, Any]] = None

    pefiles: Dict[str, Any] = Field(default_factory=dict)

    detections2pid: Dict[str, List[str]] = Field(default_factory=dict)
    detections: Dict[str, Any] = Field(default_factory=dict)

    additional: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"


class FullCAPEReport(BaseModel):
    """
    A convenient top-level structure for CAPE results as typically stored
    in a full analysis report (e.g. results["CAPE"] = CAPE.run()).
    """

    cape: CAPEPayloadsAndConfigs
    dropped: Optional[List[FileInfo]] = None
    procdump: Optional[List[FileInfo]] = None
    package: Optional[List[FileInfo]] = None
    pefiles: Optional[Dict[str, Any]] = None

    class Config:
        extra = "allow"
