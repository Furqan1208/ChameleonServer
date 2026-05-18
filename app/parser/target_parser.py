"""
Target Processing Parser - Extracts everything except strings, dirents, resources.
Keeps sections limited to name, size, characteristics, entropy.
Output: { "full": {...}, "ai_summary": {...} }
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.models.targetModel import (
    Detection,
    DetectionDetail,
    DigitalSigner,
    DirectoryEntry,
    ExtractedFile,
    GuestSigner,
    GuestSignersContainer,
    ImportedDLL,
    ImportFunction,
    PEInfo,
    ResourceEntry,
    SectionEntry,
    SelfExtractEntry,
    TargetAISummary,
    TargetFile,
    TargetModel,
    TargetSection,
    VersionInfoEntry,
    YaraMatch,
)
from app.utils.logger import get_logger

_logger = get_logger("app.parser.target")

# Limits for AI summary
_MAX_FAMILIES = 5
_MAX_SIGNERS = 3
_MAX_YARA_RULES = 20
_MAX_DIE_ENTRIES = 10
_MAX_EXTRACTED_FILES = 5
_MAX_HIGH_ENTROPY_SECTIONS = 5


class TargetParser:
    """Parser for Target section - produces full model + AI summary."""
    
    # Critical YARA patterns for family detection
    CRITICAL_YARA_PATTERNS = [
        "XWorm", "NanoCore", "DCRat", "Quasar", "AsyncRAT", "VenomRAT",
        "DarkComet", "AgentTesla", "Loki", "Formbook", "Remcos"
    ]
    
    @staticmethod
    def parse(report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse target section from report.
        Returns: { "full": {...}, "ai_summary": {...} }
        """
        try:
            # Extract raw data
            raw_target = TargetParser._extract_raw_target(report_path)
            detections = TargetParser._extract_detections(report_path)
            detections2pid = TargetParser._extract_detections2pid(report_path)
            
            if not raw_target:
                _logger.warning("No target section found in report")
                return None
            
            # Build full model (with all data except strings, dirents, full resources)
            full_result = TargetParser._parse_full_model(raw_target, detections, detections2pid)
            
            # Generate AI summary
            ai_summary = TargetParser._generate_ai_summary(full_result)
            
            return {
                "full": full_result.model_dump(exclude_none=True),
                "ai_summary": ai_summary.model_dump(exclude_none=True)
            }
            
        except Exception as e:
            _logger.exception(f"Error parsing target section: {e}")
            return None
    
    @staticmethod
    def _extract_raw_target(report_path: Path) -> Dict[str, Any]:
        """Extract raw target section from CAPE report."""
        try:
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                return data.get("target", {})
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "target" in item:
                        return item["target"]
            return {}
        except Exception as e:
            _logger.error(f"Error extracting target: {e}")
            return {}
    
    @staticmethod
    def _extract_detections(report_path: Path) -> List[Dict[str, Any]]:
        """Extract detections from root level."""
        try:
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                return data.get("detections", [])
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "detections" in item:
                        return item["detections"]
            return []
        except Exception:
            return []
    
    @staticmethod
    def _extract_detections2pid(report_path: Path) -> Dict[str, List[str]]:
        """Extract detections2pid from root level."""
        try:
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                return data.get("detections2pid", {})
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "detections2pid" in item:
                        return item["detections2pid"]
            return {}
        except Exception:
            return {}
    
    @staticmethod
    def _parse_full_model(raw_target: Dict[str, Any], detections: List[Dict],
                          detections2pid: Dict[str, List[str]]) -> TargetModel:
        """Parse raw target data into complete model."""
        
        file_data = raw_target.get("file", {})
        pe_data = file_data.get("pe", {})
        
        # === Parse PE Info (excluding strings, dirents, resources) ===
        pe_info = TargetParser._parse_pe_info(pe_data) if pe_data else None
        
        # === Parse Target File (excluding strings) ===
        target_file = TargetParser._parse_target_file(file_data, pe_info)
        
        # === Parse Target Section ===
        target_section = TargetSection(
            category=raw_target.get("category"),
            file=target_file
        )
        
        # === Parse Detections ===
        detection_objects = []
        for detection in detections:
            if isinstance(detection, dict):
                details = []
                for detail in detection.get("details", []):
                    if isinstance(detail, dict):
                        details.append(DetectionDetail(
                            Yara=detail.get("Yara"),
                            extra={k: v for k, v in detail.items() if k != "Yara"}
                        ))
                
                detection_objects.append(Detection(
                    family=detection.get("family", "Unknown"),
                    details=details
                ))
        
        return TargetModel(
            target=target_section,
            detections=detection_objects,
            detections2pid=detections2pid
        )
    
    @staticmethod
    def _parse_target_file(file_data: Dict[str, Any], pe_info: Optional[PEInfo]) -> TargetFile:
        """Parse target.file (excluding strings)."""
        
        # Parse YARA matches
        yara_matches = []
        for yara in file_data.get("yara", []):
            if isinstance(yara, dict):
                yara_matches.append(YaraMatch(
                    name=yara.get("name", ""),
                    meta=yara.get("meta"),
                    strings=yara.get("strings")[:10] if yara.get("strings") else None,
                    addresses=yara.get("addresses")
                ))
        
        cape_yara_matches = []
        for yara in file_data.get("cape_yara", []):
            if isinstance(yara, dict):
                cape_yara_matches.append(YaraMatch(
                    name=yara.get("name", ""),
                    meta=yara.get("meta"),
                    strings=yara.get("strings")[:10] if yara.get("strings") else None,
                    addresses=yara.get("addresses")
                ))
        
        # Parse self-extract (excluding strings from extracted files)
        selfextract = {}
        for key, value in file_data.get("selfextract", {}).items():
            if isinstance(value, dict):
                extracted_files = []
                for ef in value.get("extracted_files", [])[:_MAX_EXTRACTED_FILES]:
                    if isinstance(ef, dict):
                        extracted_files.append(ExtractedFile(
                            name=ef.get("name"),
                            path=ef.get("path"),
                            guest_paths=ef.get("guest_paths"),
                            size=ef.get("size"),
                            crc32=ef.get("crc32"),
                            md5=ef.get("md5"),
                            sha1=ef.get("sha1"),
                            sha256=ef.get("sha256"),
                            sha512=ef.get("sha512"),
                            sha3_384=ef.get("sha3_384"),
                            rh_hash=ef.get("rh_hash"),
                            ssdeep=ef.get("ssdeep"),
                            tlsh=ef.get("tlsh"),
                            type=ef.get("type"),
                            yara=ef.get("yara", [])[:5],
                            cape_yara=ef.get("cape_yara", [])[:5],
                            clamav=ef.get("clamav", [])[:3],
                            die=ef.get("die", [])[:5],
                            data=None,
                        ))
                
                selfextract[key] = SelfExtractEntry(
                    extracted_files=extracted_files,
                    extracted_files_time=value.get("extracted_files_time"),
                    password=value.get("password")
                )
        
        return TargetFile(
            # Basic file info
            name=file_data.get("name"),
            path=file_data.get("path"),
            guest_paths=file_data.get("guest_paths"),
            size=file_data.get("size"),
            crc32=file_data.get("crc32"),
            md5=file_data.get("md5"),
            sha1=file_data.get("sha1"),
            sha256=file_data.get("sha256"),
            sha512=file_data.get("sha512"),
            sha3_384=file_data.get("sha3_384"),
            rh_hash=file_data.get("rh_hash"),
            ssdeep=file_data.get("ssdeep"),
            tlsh=file_data.get("tlsh"),
            type=file_data.get("type"),
            # CAPE classification
            cape_type=file_data.get("cape_type"),
            cape_type_code=file_data.get("cape_type_code"),
            # Detection results
            yara=yara_matches,
            cape_yara=cape_yara_matches,
            clamav=file_data.get("clamav", [])[:10],
            # PE info
            pe=pe_info,
            # Self-extract
            selfextract=selfextract,
            # Strings - EXCLUDED
            strings=None,
            # Die info
            die=file_data.get("die"),
            # Data
            data=None
        )
    
    @staticmethod
    def _parse_pe_info(pe_data: Dict[str, Any]) -> PEInfo:
        """Parse PE info (excluding dirents, resources)."""
        
        # Parse guest signers
        guest_signers = None
        gs_data = pe_data.get("guest_signers", {})
        if gs_data:
            aux_signers = []
            for signer in gs_data.get("aux_signers", []):
                if isinstance(signer, dict):
                    aux_signers.append(GuestSigner(
                        name=signer.get("name"),
                        issued_to=signer.get("Issued to"),
                        issued_by=signer.get("Issued by"),
                        expires=signer.get("Expires"),
                        sha1_hash=signer.get("SHA1 hash"),
                        timestamp=signer.get("aux_timestamp")
                    ))
            
            guest_signers = GuestSignersContainer(
                aux_sha1=gs_data.get("aux_sha1"),
                aux_timestamp=gs_data.get("aux_timestamp"),
                aux_valid=gs_data.get("aux_valid", False),
                aux_error=gs_data.get("aux_error", False),
                aux_error_desc=gs_data.get("aux_error_desc"),
                aux_signers=aux_signers
            )
        
        # Parse digital signers
        digital_signers = []
        for signer in pe_data.get("digital_signers", [])[:_MAX_SIGNERS]:
            if isinstance(signer, dict):
                digital_signers.append(DigitalSigner(
                    subject=signer.get("subject"),
                    issuer=signer.get("issuer"),
                    serial_number=signer.get("serial_number"),
                    sha1_fingerprint=signer.get("sha1_fingerprint"),
                    sha256_fingerprint=signer.get("sha256_fingerprint"),
                    not_before=signer.get("not_before"),
                    not_after=signer.get("not_after"),
                    subject_countryName=signer.get("subject_countryName"),
                    subject_organizationName=signer.get("subject_organizationName"),
                    subject_organizationalUnitName=signer.get("subject_organizationalUnitName"),
                    issuer_countryName=signer.get("issuer_countryName"),
                    issuer_organizationName=signer.get("issuer_organizationName"),
                ))
        
        # Parse imports
        imports_dict = {}
        for dll_name, dll_data in pe_data.get("imports", {}).items():
            if isinstance(dll_data, dict):
                imports_list = []
                for imp in dll_data.get("imports", [])[:20]:
                    if isinstance(imp, dict):
                        imports_list.append(ImportFunction(
                            address=imp.get("address"),
                            name=imp.get("name")
                        ))
                imports_dict[dll_name] = ImportedDLL(
                    dll=dll_data.get("dll", dll_name),
                    imports=imports_list
                )
        
        # Parse sections (ONLY name, size_of_data, characteristics, entropy)
        sections = []
        for sec in pe_data.get("sections", []):
            if isinstance(sec, dict):
                sections.append(SectionEntry(
                    name=sec.get("name", ""),
                    size_of_data=sec.get("size_of_data"),
                    characteristics=sec.get("characteristics"),
                    entropy=sec.get("entropy"),
                ))
        
        # Parse versioninfo (KEEP - useful for legitimacy detection)
        versioninfo = []
        for vinfo in pe_data.get("versioninfo", []):
            if isinstance(vinfo, dict):
                versioninfo.append(VersionInfoEntry(
                    name=vinfo.get("name", ""),
                    value=vinfo.get("value")
                ))
        
        # dirents - EXCLUDED completely
        # resources - EXCLUDED completely
        
        return PEInfo(
            guest_signers=guest_signers,
            digital_signers=digital_signers,
            imagebase=pe_data.get("imagebase"),
            entrypoint=pe_data.get("entrypoint"),
            ep_bytes=pe_data.get("ep_bytes"),
            reported_checksum=pe_data.get("reported_checksum"),
            actual_checksum=pe_data.get("actual_checksum"),
            osversion=pe_data.get("osversion"),
            pdbpath=pe_data.get("pdbpath"),
            peid_signatures=pe_data.get("peid_signatures"),
            imphash=pe_data.get("imphash"),
            timestamp=pe_data.get("timestamp"),
            imported_dll_count=pe_data.get("imported_dll_count"),
            imports=imports_dict,
            exported_dll_name=pe_data.get("exported_dll_name"),
            exports=pe_data.get("exports", [])[:20],
            dirents=[],  # EXCLUDED
            sections=sections,
            overlay=pe_data.get("overlay"),
            resources=[],  # EXCLUDED
            versioninfo=versioninfo,  # KEPT for AI summary
            icon=None,
            icon_hash=pe_data.get("icon_hash"),
            icon_fuzzy=pe_data.get("icon_fuzzy"),
            icon_dhash=pe_data.get("icon_dhash"),
        )
    
    @staticmethod
    def _generate_ai_summary(full: TargetModel) -> TargetAISummary:
        """Generate compact AI summary from full model."""
        summary = TargetAISummary()
        
        target_file = full.target.file if full.target else None
        
        if not target_file:
            return summary
        
        # === Basic Identity ===
        summary.sha256 = target_file.sha256
        summary.md5 = target_file.md5
        summary.file_name = target_file.name
        summary.file_size = target_file.size
        summary.file_type = target_file.type[:150] if target_file.type else None
        
        # === CAPE Classification ===
        summary.cape_type = target_file.cape_type
        summary.cape_type_code = target_file.cape_type_code
        
        # === Detected Families ===
        families = []
        for detection in full.detections:
            if detection.family and detection.family not in families:
                families.append(detection.family)
        summary.detected_families = families[:_MAX_FAMILIES]
        
        # === Die Info ===
        if target_file.die:
            summary.die_info = target_file.die[:_MAX_DIE_ENTRIES]
        
        # === Signing Info ===
        if target_file.pe and target_file.pe.digital_signers:
            summary.is_signed = True
            for signer in target_file.pe.digital_signers[:_MAX_SIGNERS]:
                if signer.subject:
                    summary.signers.append(signer.subject)
            if target_file.pe.guest_signers:
                summary.signing_error = target_file.pe.guest_signers.aux_error_desc
        
        # === .NET Indicators ===
        if target_file.type and ".Net" in target_file.type:
            summary.is_dotnet = True
        
        # Check for obfuscation in die
        obfuscation_keywords = ["Eazfuscator", "Confuser", "Obfuscator", "Reacto"]
        if target_file.die:
            for die in target_file.die:
                if any(kw.lower() in die.lower() for kw in obfuscation_keywords):
                    summary.is_obfuscated = True
                    break
        
        # === PE Indicators ===
        if target_file.pe:
            summary.imphash = target_file.pe.imphash
            summary.compile_timestamp = target_file.pe.timestamp
            summary.entrypoint = target_file.pe.entrypoint
            summary.pdb_path = target_file.pe.pdbpath
            
            # High entropy sections (packing indicator)
            for section in target_file.pe.sections:
                if section.entropy and section.entropy > 7.0:
                    summary.high_entropy_sections.append(section.name)
                    summary.is_packed = True
            summary.high_entropy_sections = summary.high_entropy_sections[:_MAX_HIGH_ENTROPY_SECTIONS]
        
        # === Version Info (For legitimacy detection) ===
        if target_file.pe and target_file.pe.versioninfo:
            for vinfo in target_file.pe.versioninfo:
                if vinfo.name == "CompanyName":
                    summary.company_name = vinfo.value
                elif vinfo.name == "ProductName":
                    summary.product_name = vinfo.value
                elif vinfo.name == "FileDescription":
                    summary.file_description = vinfo.value
                elif vinfo.name == "OriginalFilename":
                    summary.original_filename = vinfo.value
                elif vinfo.name == "LegalCopyright":
                    summary.legal_copyright = vinfo.value
        
        # === Self-Extraction ===
        if target_file.selfextract:
            summary.has_self_extract = True
            for method, extract_data in target_file.selfextract.items():
                summary.self_extract_method = method
                summary.extracted_files_count = len(extract_data.extracted_files)
                for ef in extract_data.extracted_files[:3]:
                    if ef.type and ef.type not in summary.extracted_file_types:
                        summary.extracted_file_types.append(ef.type[:50])
                break
        
        # === YARA Summary ===
        summary.yara_rule_count = len(target_file.yara)
        summary.cape_yara_rule_count = len(target_file.cape_yara)
        
        # Extract critical YARA rules (family names)
        critical_rules = []
        for yara in target_file.yara + target_file.cape_yara:
            for pattern in TargetParser.CRITICAL_YARA_PATTERNS:
                if pattern.lower() in yara.name.lower():
                    if yara.name not in critical_rules:
                        critical_rules.append(yara.name)
        summary.critical_yara_rules = critical_rules[:5]
        
        # === Process Mappings ===
        summary.infected_processes = full.detections2pid
        
        # === Generate Quick Summary ===
        summary.generate_summary()
        
        return summary


# ============================================================
# Legacy/Compatibility Functions
# ============================================================

def parse_target_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Main entry point - returns {full, ai_summary}."""
    return TargetParser.parse(report_path)


def process_target_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Legacy alias."""
    return parse_target_section(report_path)


# ============================================================
# Self-Execution
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        _logger.info("Usage: python target_parser.py <cape_report.json>")
        sys.exit(1)
    
    report_file = Path(sys.argv[1])
    result = parse_target_section(report_file)
    
    if result:
        print("\n" + "=" * 60)
        print("AI SUMMARY (What goes to LLM)")
        print("=" * 60)
        print(json.dumps(result.get("ai_summary", {}), indent=2))
        
        print("\n" + "=" * 60)
        print("FULL MODEL STATISTICS")
        print("=" * 60)
        full = result.get("full", {})
        target = full.get("target", {})
        file_data = target.get("file", {})
        
        original_size_estimate = 500 * 1024
        current_size = len(json.dumps(result))
        
        print(f"File: {file_data.get('name', 'N/A')}")
        print(f"Size: {file_data.get('size', 'N/A')} bytes")
        print(f"SHA256: {file_data.get('sha256', '')[:32]}...")
        print(f"CAPE Type: {file_data.get('cape_type', 'N/A')}")
        print(f"Detections: {len(full.get('detections', []))}")
        print(f"detections2pid: {len(full.get('detections2pid', {}))} PIDs")
        print(f"YARA Rules: {len(file_data.get('yara', []))}")
        print(f"Sections: {len(file_data.get('pe', {}).get('sections', []))}")
        
        print("\n" + "=" * 60)
        print("SIZE COMPARISON")
        print("=" * 60)
        print(f"Estimated original size: {original_size_estimate:,} bytes")
        print(f"Current output size: {current_size:,} bytes")
        print(f"Reduction: {(1 - current_size / original_size_estimate) * 100:.1f}%")
        
        ai_summary = result.get("ai_summary", {})
        print(f"\nQuick Summary: {ai_summary.get('quick_summary', 'N/A')}")
    else:
        _logger.error("Failed to parse target section")
        sys.exit(1)