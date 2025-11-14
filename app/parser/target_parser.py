import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class GuestSigner(BaseModel):
    name: Optional[str] = Field(None)
    issued_to: Optional[str] = Field(None, alias="Issued to")
    issued_by: Optional[str] = Field(None, alias="Issued by")
    expires: Optional[str] = Field(None, alias="Expires")
    sha1_hash: Optional[str] = Field(None, alias="SHA1 hash")


class DigitalSigner(BaseModel):
    subject: Optional[str] = Field(None, alias="subject_commonName")
    issuer: Optional[str] = Field(None, alias="issuer_commonName")
    country: Optional[str] = Field(None, alias="subject_countryName")
    valid_from: Optional[str] = Field(None, alias="not_before")
    valid_to: Optional[str] = Field(None, alias="not_after")
    sha1_fingerprint: Optional[str] = Field(None, alias="sha1_fingerprint")
    sha256_fingerprint: Optional[str] = Field(None, alias="sha256_fingerprint")


class PESigningInfo(BaseModel):
    signed: bool = False
    signing_timestamp: Optional[str] = None
    signing_error: Optional[str] = None
    guest_signers: List[GuestSigner] = Field(default_factory=list)
    digital_signers: List[DigitalSigner] = Field(default_factory=list)


class ExtractedFile(BaseModel):
    name: Optional[str] = None
    path: Optional[str] = None
    size: Optional[int] = None
    type: Optional[str] = None
    crc32: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    sha3_384: Optional[str] = None
    extracted_from: Optional[List[str]] = Field(default_factory=list)
    die_summary: Optional[List[str]] = None


class SelfExtractInfo(BaseModel):
    extracted_files_count: int = 0
    extracted_files_time: Optional[float] = None
    extracted_files: List[ExtractedFile] = Field(default_factory=list)
    password_used: Optional[str] = None


class ImportInfo(BaseModel):
    dll: str
    count: int
    top_imports: List[str]


class ExportInfo(BaseModel):
    count: int
    names: Optional[List[str]] = None


class DirectoryEntry(BaseModel):
    name: str
    virtual_address: Optional[str] = None
    size: Optional[str] = None


class SectionInfo(BaseModel):
    name: str
    virtual_address: Optional[str] = None
    raw_address: Optional[str] = None
    virtual_size: Optional[str] = None
    raw_size: Optional[str] = None
    entropy: Optional[float] = None
    flags: Optional[str] = None


class OverlayInfo(BaseModel):
    offset: Optional[str] = None
    size: Optional[str] = None


class ResourceInfo(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None
    offset: Optional[str] = None
    size: Optional[str] = None
    entropy: Optional[float] = None
    language: Optional[str] = None


class PEBasicInfo(BaseModel):
    imagebase: Optional[str] = None
    entrypoint: Optional[str] = None
    ep_bytes: Optional[str] = None
    reported_checksum: Optional[str] = None
    actual_checksum: Optional[str] = None
    osversion: Optional[str] = None
    pdbpath: Optional[str] = None
    peid_signatures: Optional[List[str]] = None
    imported_dlls: List[ImportInfo] = Field(default_factory=list)
    exports_summary: Optional[ExportInfo] = None
    exported_dll_name: Optional[str] = None
    directories: List[DirectoryEntry] = Field(default_factory=list)
    sections: List[SectionInfo] = Field(default_factory=list)
    overlay: Optional[OverlayInfo] = None
    resources: List[ResourceInfo] = Field(default_factory=list)
    imphash: Optional[str] = None
    timestamp: Optional[str] = None
    icon_hash: Optional[str] = None
    icon_fuzzy: Optional[str] = None
    icon_dhash: Optional[str] = None


class PEStructureParser:
    @staticmethod
    def parse_imports(imports_data: Dict[str, Any]) -> List[ImportInfo]:
        imports_summary = []
        if isinstance(imports_data, dict):
            for dll_name, dll_info in imports_data.items():
                if isinstance(dll_info, dict):
                    imports_list = dll_info.get("imports", [])
                    imports_summary.append(
                        ImportInfo(
                            dll=dll_info.get("dll", dll_name),
                            count=len(imports_list),
                            top_imports=[
                                imp.get("name")
                                for imp in imports_list[:5]
                                if imp.get("name")
                            ],
                        )
                    )
        return imports_summary

    @staticmethod
    def parse_exports(exports_data: List[Any]) -> Optional[ExportInfo]:
        if not exports_data:
            return None

        names = []
        for exp in exports_data[:10]:
            if isinstance(exp, dict) and exp.get("name"):
                names.append(exp["name"])
            elif isinstance(exp, str):
                names.append(exp)

        return ExportInfo(count=len(exports_data), names=names if names else None)

    @staticmethod
    def parse_directories(directories_data: List[Dict]) -> List[DirectoryEntry]:
        directories = []
        for entry in directories_data[:15]:
            if isinstance(entry, dict):
                directories.append(
                    DirectoryEntry(
                        name=entry.get("name", ""),
                        virtual_address=entry.get("virtual_address"),
                        size=entry.get("size"),
                    )
                )
        return directories

    @staticmethod
    def parse_sections(sections_data: List[Dict]) -> List[SectionInfo]:
        sections = []
        for sec in sections_data:
            if isinstance(sec, dict):
                sections.append(
                    SectionInfo(
                        name=sec.get("name", ""),
                        virtual_address=sec.get("virtual_address"),
                        raw_address=sec.get("raw_address"),
                        virtual_size=sec.get("virtual_size"),
                        raw_size=sec.get("size_of_data"),
                        entropy=sec.get("entropy"),
                        flags=sec.get("characteristics"),
                    )
                )
        return sections

    @staticmethod
    def parse_overlay(overlay_info: Dict[str, Any]) -> Optional[OverlayInfo]:
        if overlay_info and isinstance(overlay_info, dict):
            return OverlayInfo(
                offset=overlay_info.get("offset"),
                size=overlay_info.get("size"),
            )
        return None

    @staticmethod
    def parse_resources(resources_data: List[Dict]) -> List[ResourceInfo]:
        resources = []
        for res in resources_data[:10]:
            if isinstance(res, dict):
                resources.append(
                    ResourceInfo(
                        name=res.get("name"),
                        type=res.get("name"),
                        offset=res.get("offset"),
                        size=res.get("size"),
                        entropy=res.get("entropy"),
                        language=res.get("language"),
                    )
                )
        return resources

    @classmethod
    def parse_pe_data(cls, pe_data: Dict[str, Any]) -> PEBasicInfo:
        if not pe_data:
            return PEBasicInfo()

        ep_bytes = pe_data.get("ep_bytes")
        shortened_ep_bytes = (
            ep_bytes[:20] + "..." if ep_bytes and len(ep_bytes) > 20 else ep_bytes
        )

        return PEBasicInfo(
            imagebase=pe_data.get("imagebase"),
            entrypoint=pe_data.get("entrypoint"),
            ep_bytes=shortened_ep_bytes,
            reported_checksum=pe_data.get("reported_checksum"),
            actual_checksum=pe_data.get("actual_checksum"),
            osversion=pe_data.get("osversion"),
            pdbpath=pe_data.get("pdbpath"),
            peid_signatures=pe_data.get("peid_signatures") or [],
            imported_dlls=cls.parse_imports(pe_data.get("imports", {})),
            exports_summary=cls.parse_exports(pe_data.get("exports", [])),
            exported_dll_name=pe_data.get("exported_dll_name"),
            directories=cls.parse_directories(pe_data.get("dirents", [])),
            sections=cls.parse_sections(pe_data.get("sections", [])),
            overlay=cls.parse_overlay(pe_data.get("overlay", {})),
            resources=cls.parse_resources(pe_data.get("resources", [])),
            imphash=pe_data.get("imphash"),
            timestamp=pe_data.get("timestamp"),
            icon_hash=pe_data.get("icon_hash"),
            icon_fuzzy=pe_data.get("icon_fuzzy"),
            icon_dhash=pe_data.get("icon_dhash"),
        )


class FileTarget(BaseModel):
    category: str = "unknown"
    file_name: Optional[str] = None
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    file_type: Optional[str] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    sha512: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    yara_hits: int = 0
    cape_yara_hits: int = 0
    clamav_hits: int = 0
    pe_info: Optional[PESigningInfo] = None
    pe_structure: Optional[PEBasicInfo] = None
    die_summary: List[str] = Field(default_factory=list)
    self_extract: Optional[SelfExtractInfo] = None
    cape_type_code: Optional[int] = None
    cape_type: Optional[str] = None

    @classmethod
    def from_cape_data(cls, target_data: Dict[str, Any]) -> "FileTarget":
        file_data = target_data.get("file", {})
        pe_data = file_data.get("pe", {}) or {}

        pe_info = cls._parse_pe_signing_info(pe_data)
        die_summary = file_data.get("die", [])
        self_extract = cls._parse_self_extract_info(file_data)

        cape_type_code = file_data.get("cape_type_code")
        cape_type = file_data.get("cape_type")

        return cls(
            category=target_data.get("category", "unknown"),
            file_name=file_data.get("name"),
            file_path=file_data.get("path"),
            file_size=file_data.get("size"),
            file_type=file_data.get("type"),
            md5=file_data.get("md5"),
            sha1=file_data.get("sha1"),
            sha256=file_data.get("sha256"),
            sha512=file_data.get("sha512"),
            ssdeep=file_data.get("ssdeep"),
            tlsh=file_data.get("tlsh"),
            yara_hits=len(file_data.get("yara", [])),
            cape_yara_hits=len(file_data.get("cape_yara", [])),
            clamav_hits=len(file_data.get("clamav", [])),
            pe_info=pe_info,
            pe_structure=PEStructureParser.parse_pe_data(pe_data),
            die_summary=die_summary if isinstance(die_summary, list) else [],
            self_extract=self_extract,
            cape_type_code=cape_type_code,
            cape_type=cape_type,
        )

    @staticmethod
    def _parse_pe_signing_info(pe_data: Dict[str, Any]) -> Optional[PESigningInfo]:
        if not pe_data:
            return None

        guest_signers = pe_data.get("guest_signers", {}) or {}
        digital_signers = pe_data.get("digital_signers", []) or []

        return PESigningInfo(
            signed=bool(digital_signers),
            signing_timestamp=guest_signers.get("aux_timestamp"),
            signing_error=guest_signers.get("aux_error_desc"),
            guest_signers=[
                GuestSigner(**signer)
                for signer in guest_signers.get("aux_signers", [])[:6]
                if isinstance(signer, dict)
            ],
            digital_signers=[
                DigitalSigner(**signer)
                for signer in digital_signers[:6]
                if isinstance(signer, dict)
            ],
        )

    @staticmethod
    def _parse_self_extract_info(
        file_data: Dict[str, Any],
    ) -> Optional[SelfExtractInfo]:
        selfextract_data = file_data.get("selfextract", {})
        extracted_files = []

        if selfextract_data and isinstance(selfextract_data, dict):
            overlay_data = selfextract_data.get("overlay", {})
            if overlay_data and isinstance(overlay_data, dict):
                extracted_files_data = overlay_data.get("extracted_files", [])
                for ef in extracted_files_data[:5]:
                    if isinstance(ef, dict):
                        extracted_files.append(
                            ExtractedFile(
                                name=ef.get("name"),
                                path=ef.get("path"),
                                size=ef.get("size"),
                                type=ef.get("type"),
                                crc32=ef.get("crc32"),
                                md5=ef.get("md5"),
                                sha1=ef.get("sha1"),
                                sha256=ef.get("sha256"),
                                sha512=ef.get("sha512"),
                                ssdeep=ef.get("ssdeep"),
                                tlsh=ef.get("tlsh"),
                                sha3_384=ef.get("sha3_384"),
                                extracted_from=ef.get("guest_paths", []),
                                die_summary=ef.get("die", []),
                            )
                        )

        if not extracted_files and not selfextract_data:
            return None

        overlay_data = selfextract_data.get("overlay", {}) if selfextract_data else {}
        return SelfExtractInfo(
            extracted_files_count=len(extracted_files),
            extracted_files_time=overlay_data.get("extracted_files_time"),
            extracted_files=extracted_files,
            password_used=overlay_data.get("password", ""),
        )


class CompactJSONEncoder(json.JSONEncoder):
    def encode(self, o):
        if (
            isinstance(o, list)
            and len(o) > 0
            and all(isinstance(item, dict) for item in o)
        ):
            return "[\n" + ",\n".join(self._format_dict(item) for item in o) + "\n]"
        return super().encode(o)

    def _format_dict(self, obj):
        items = []
        for key, value in obj.items():
            if value is None:
                continue
            items.append(f'"{key}": {json.dumps(value)}')
        return "  {" + ", ".join(items) + "}"


class CAPEReportProcessor:
    @staticmethod
    def extract_target_section(report_path: Path) -> Dict[str, Any]:
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                report = json.load(f)
            return report.get("target", {})
        except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
            print(f"Error reading report file: {e}")
            return {}

    @staticmethod
    def clean_target_data(target_data: Dict[str, Any]) -> Dict[str, Any]:
        model = FileTarget.from_cape_data(target_data)
        return model.model_dump(exclude_none=True, by_alias=True)

    @staticmethod
    def save_cleaned_data(cleaned_data: Dict[str, Any], output_file: str) -> None:
        try:

            def compact_serialize(obj):
                if isinstance(obj, dict):
                    return {
                        k: compact_serialize(v) for k, v in obj.items() if v is not None
                    }
                elif isinstance(obj, list):
                    return [compact_serialize(item) for item in obj]
                else:
                    return obj

            compact_data = compact_serialize(cleaned_data)

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(
                    [compact_data],
                    f,
                    indent=2,
                    ensure_ascii=False,
                    cls=CompactJSONEncoder,
                )
            print(f"[+] Successfully saved parsed target data to {output_file}")
        except Exception as e:
            print(f"Error saving output file: {e}")

    @staticmethod
    def format_resources_compact(resources: List[Dict]) -> List[Dict]:
        compact_resources = []
        for resource in resources:
            compact_resource = {}
            for key, value in resource.items():
                if value is not None:
                    compact_resource[key] = value
            compact_resources.append(compact_resource)
        return compact_resources

    def process_report(self, report_file: Path) -> None:
        if not report_file.exists():
            print(f"Error: File '{report_file}' not found")
            sys.exit(1)

        output_file = report_file.stem + "_target_parsed.json"

        print(f"[*] Processing CAPE report: {report_file}")

        target_section = self.extract_target_section(report_file)
        if not target_section:
            print("[-] No target section found in the report")
            sys.exit(1)

        print("[*] Parsing target data...")
        cleaned = self.clean_target_data(target_section)

        if cleaned.get("pe_structure", {}).get("resources"):
            resources = cleaned["pe_structure"]["resources"]
            cleaned["pe_structure"]["resources"] = self.format_resources_compact(
                resources
            )

        print("[*] Saving results...")
        self.save_cleaned_data(cleaned, output_file)

        self._print_summary(cleaned)

    @staticmethod
    def _print_summary(cleaned_data: Dict[str, Any]) -> None:
        print("\n[+] Summary:")
        print(f"    File: {cleaned_data.get('file_name')}")
        print(f"    Size: {cleaned_data.get('file_size')} bytes")
        print(f"    SHA256: {cleaned_data.get('sha256')}")
        print(f"    Type: {cleaned_data.get('file_type')}")
        print(f"    Signed: {cleaned_data.get('pe_info', {}).get('signed', False)}")
        print(f"    YARA Hits: {cleaned_data.get('yara_hits', 0)}")

        self_extract = cleaned_data.get("self_extract", {})
        extracted_count = self_extract.get("extracted_files_count", 0)
        print(f"    Extracted Files: {extracted_count}")

        if extracted_count > 0:
            print(
                f"Extraction Time: {self_extract.get('extracted_files_time')} seconds"
            )
            for ef in self_extract.get("extracted_files", [])[:3]:
                print(f"      - {ef.get('name')} ({ef.get('size')} bytes)")

        if cleaned_data.get("cape_type") or cleaned_data.get("cape_type_code"):
            print(
                f"CAPE Type: {cleaned_data.get('cape_type')} (Code: {cleaned_data.get('cape_type_code')})"  # noqa: E501
            )


def main():
    if len(sys.argv) < 2:
        print("Usage: python target_model.py <cape_report.json>")
        print("Example: python target_model.py analysis_report.json")
        sys.exit(1)

    report_file = Path(sys.argv[1])
    processor = CAPEReportProcessor()
    processor.process_report(report_file)


if __name__ == "__main__":
    main()
