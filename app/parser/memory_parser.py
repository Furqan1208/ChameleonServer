"""
Memory Parser - Parses procdump, dropped, and procmemory sections.
Output: { "full": {...}, "ai_summary": {...} }
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.models.procmemoryModel import (
    DroppedData,
    ExtractedFile,
    MemoryExtractedPE,
    MemoryMap,
    MemoryYaraHit,
    ProcMemoryProcessingResult,
    ProcessArtifactsAISummary,
    ProcessArtifactsResult,
    ProcessMemoryEntry,
    ProcdumpData,
    ProcmemoryData,
    YaraHit,
)
from app.utils.logger import get_logger

_logger = get_logger("app.parser.memory")

# Limits
_MAX_PROCDUMP_FILES = 10
_MAX_DROPPED_FILES = 15
_MAX_MEMORY_DUMPS = 10
_MAX_EXTRACTED_PE_PER_DUMP = 5
_MAX_YARA_RULES_PER_FILE = 10


class MemoryParser:
    """Parser for procdump, dropped, and procmemory sections."""
    
    @staticmethod
    def parse(report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse procdump, dropped, and procmemory sections from report.
        Returns: { "full": {...}, "ai_summary": {...} }
        """
        try:
            # Extract raw data from report
            raw_procdump = MemoryParser._extract_section(report_path, "procdump")
            raw_dropped = MemoryParser._extract_section(report_path, "dropped")
            raw_procmemory = MemoryParser._extract_section(report_path, "procmemory")
            
            # Parse each section
            procdump_data = MemoryParser._parse_procdump(raw_procdump) if raw_procdump else ProcdumpData()
            dropped_data = MemoryParser._parse_dropped(raw_dropped) if raw_dropped else DroppedData()
            procmemory_data = MemoryParser._parse_procmemory(raw_procmemory) if raw_procmemory else ProcmemoryData()
            
            # Build full result
            full_result = ProcessArtifactsResult(
                procdump=procdump_data,
                dropped=dropped_data,
                procmemory=procmemory_data
            )
            
            # Generate AI summary
            ai_summary = MemoryParser._generate_ai_summary(full_result)
            
            return {
                "full": full_result.model_dump(exclude_none=True),
                "ai_summary": ai_summary.model_dump(exclude_none=True)
            }
            
        except Exception as e:
            _logger.exception(f"Error parsing memory sections: {e}")
            return None
    
    @staticmethod
    def _extract_section(report_path: Path, section_name: str) -> List[Any]:
        """Extract a section from the CAPE report."""
        try:
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                return data.get(section_name, [])
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and section_name in item:
                        return item[section_name]
            return []
        except Exception as e:
            _logger.error(f"Error extracting {section_name}: {e}")
            return []
    
    @staticmethod
    def _parse_procdump(raw_data: List[Dict[str, Any]]) -> ProcdumpData:
        """Parse procdump section."""
        files = []
        pe_count = 0
        file_types = {}
        
        for item in raw_data[:_MAX_PROCDUMP_FILES]:
            # Remove unwanted fields BEFORE parsing
            cleaned_item = MemoryParser._clean_extracted_file(item)
            extracted_file = MemoryParser._parse_extracted_file(cleaned_item)
            if extracted_file:
                files.append(extracted_file)
                if "PE32" in str(extracted_file.type):
                    pe_count += 1
                file_type = (extracted_file.type or "Unknown")[:50]
                file_types[file_type] = file_types.get(file_type, 0) + 1
        
        return ProcdumpData(
            files=files,
            total_files=len(files),
            total_pe_files=pe_count,
            file_types=file_types
        )
    
    @staticmethod
    def _parse_dropped(raw_data: List[Dict[str, Any]]) -> DroppedData:
        """Parse dropped section."""
        files = []
        suspicious_paths = []
        file_types = {}
        
        suspicious_patterns = ["temp", "programdata", "appdata", "windows\\temp"]
        
        for item in raw_data[:_MAX_DROPPED_FILES]:
            # Clean the item first
            cleaned_item = MemoryParser._clean_extracted_file(item)
            extracted_file = MemoryParser._parse_extracted_file(cleaned_item)
            if extracted_file:
                files.append(extracted_file)
                
                # Check for suspicious paths
                guest_paths = extracted_file.guest_paths or []
                for path in guest_paths:
                    path_lower = str(path).lower()
                    for pattern in suspicious_patterns:
                        if pattern in path_lower:
                            suspicious_paths.append(str(path)[:100])
                            break
                
                file_type = (extracted_file.type or "Unknown")[:50]
                file_types[file_type] = file_types.get(file_type, 0) + 1
        
        return DroppedData(
            files=files,
            total_files=len(files),
            file_types=file_types,
            suspicious_paths=list(set(suspicious_paths))[:10]
        )
    
    @staticmethod
    def _clean_extracted_file(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove unwanted fields from extracted file data:
        - strings
        - dirents
        - resources (full)
        - versioninfo (full)
        - data field
        - icon (base64)
        - Keep only name, size, entropy for sections
        """
        if not isinstance(data, dict):
            return data
        
        # Make a copy to avoid modifying original
        cleaned = data.copy()
        
        # Remove top-level unwanted fields
        remove_fields = ["strings", "data", "dirents", "resources", "versioninfo", "icon"]
        for field in remove_fields:
            cleaned.pop(field, None)
        
        # Clean pe structure if present
        if "pe" in cleaned and isinstance(cleaned["pe"], dict):
            pe = cleaned["pe"].copy()
            
            # Remove unwanted PE fields
            pe.pop("strings", None)
            pe.pop("dirents", None)
            pe.pop("resources", None)
            pe.pop("versioninfo", None)
            pe.pop("icon", None)
            pe.pop("ep_bytes", None)  # Not needed for AI
            
            # Clean sections - keep only name, size_of_data, characteristics, entropy
            if "sections" in pe and isinstance(pe["sections"], list):
                cleaned_sections = []
                for section in pe["sections"]:
                    if isinstance(section, dict):
                        cleaned_section = {
                            "name": section.get("name"),
                            "size_of_data": section.get("size_of_data"),
                            "characteristics": section.get("characteristics"),
                            "entropy": section.get("entropy"),
                        }
                        # Remove None values
                        cleaned_section = {k: v for k, v in cleaned_section.items() if v is not None}
                        if cleaned_section:
                            cleaned_sections.append(cleaned_section)
                pe["sections"] = cleaned_sections
            
            # Clean imports - keep only DLL names, not individual functions
            if "imports" in pe and isinstance(pe["imports"], dict):
                cleaned_imports = {}
                for dll_name, dll_data in pe["imports"].items():
                    if isinstance(dll_data, dict):
                        cleaned_imports[dll_name] = {"dll": dll_data.get("dll", dll_name)}
                    else:
                        cleaned_imports[dll_name] = {"dll": dll_name}
                pe["imports"] = cleaned_imports
            
            # Clean digital_signers - keep only essential fields
            if "digital_signers" in pe and isinstance(pe["digital_signers"], list):
                cleaned_signers = []
                for signer in pe["digital_signers"]:
                    if isinstance(signer, dict):
                        cleaned_signers.append({
                            "subject": signer.get("subject"),
                            "issuer": signer.get("issuer"),
                            "sha256_fingerprint": signer.get("sha256_fingerprint"),
                            "not_before": signer.get("not_before"),
                            "not_after": signer.get("not_after"),
                        })
                pe["digital_signers"] = cleaned_signers
            
            # Clean guest_signers
            if "guest_signers" in pe and isinstance(pe["guest_signers"], dict):
                gs = pe["guest_signers"]
                pe["guest_signers"] = {
                    "aux_error_desc": gs.get("aux_error_desc"),
                    "aux_valid": gs.get("aux_valid", False),
                }
            
            cleaned["pe"] = pe
        
        return cleaned
    
    @staticmethod
    def _parse_extracted_file(data: Dict[str, Any]) -> Optional[ExtractedFile]:
        """Parse an extracted file (procdump or dropped) from already cleaned data."""
        if not data:
            return None
        
        # Parse YARA hits - keep ONLY rule names
        yara_rules = []
        for yara in data.get("yara", []):
            if isinstance(yara, dict):
                name = yara.get("name")
                if name:
                    yara_rules.append(name)
        
        cape_yara_rules = []
        for yara in data.get("cape_yara", []):
            if isinstance(yara, dict):
                name = yara.get("name")
                if name:
                    cape_yara_rules.append(name)
        
        # Parse guest_paths (handle both string and list)
        guest_paths = data.get("guest_paths")
        if isinstance(guest_paths, str):
            guest_paths = [guest_paths]
        elif not isinstance(guest_paths, list):
            guest_paths = None

        pid_value = data.get("pid")
        if pid_value in (None, ""):
            pid_value = None
        else:
            try:
                pid_value = int(pid_value)
            except (TypeError, ValueError):
                pid_value = None
        
        # Parse self-extract info
        selfextract_data = data.get("selfextract", {})
        selfextract_method = None
        extracted_files_count = 0
        if selfextract_data:
            for method, extract_info in selfextract_data.items():
                selfextract_method = method
                if isinstance(extract_info, dict):
                    extracted_files = extract_info.get("extracted_files", [])
                    extracted_files_count = len(extracted_files)
                break
        
        # Handle name (can be string or list)
        name = data.get("name")
        if isinstance(name, list) and name:
            name = name[0]
        
        return ExtractedFile(
            name=name,
            path=data.get("path"),
            size=data.get("size"),
            type=data.get("type")[:200] if data.get("type") else None,
            md5=data.get("md5"),
            sha1=data.get("sha1"),
            sha256=data.get("sha256"),
            sha512=data.get("sha512"),
            sha3_384=data.get("sha3_384"),
            crc32=data.get("crc32"),
            ssdeep=data.get("ssdeep"),
            tlsh=data.get("tlsh"),
            cape_type=data.get("cape_type"),
            cape_type_code=data.get("cape_type_code"),
            process_name=data.get("process_name"),
            process_path=data.get("process_path"),
            pid=pid_value,
            virtual_address=data.get("virtual_address"),
            guest_paths=guest_paths[:3] if guest_paths else None,
            yara_rules=yara_rules[:_MAX_YARA_RULES_PER_FILE],
            cape_yara_rules=cape_yara_rules[:_MAX_YARA_RULES_PER_FILE],
            clamav_hits=[str(c) for c in data.get("clamav", [])[:5]],
            die=data.get("die", [])[:5],
            selfextract_method=selfextract_method,
            extracted_files_count=extracted_files_count,
            data=None,  # EXCLUDED
        )
    
    @staticmethod
    def _parse_procmemory(raw_data: List[Dict[str, Any]]) -> ProcmemoryData:
        """Parse procmemory section - address_space COMPLETELY REMOVED."""
        memory_dumps = []
        dumps_with_yara = 0
        dumps_with_shellcode = 0
        total_extracted_pe = 0
        
        for item in raw_data[:_MAX_MEMORY_DUMPS]:
            # Clean the memory dump
            cleaned_item = MemoryParser._clean_memory_dump(item)
            memory_dump = MemoryParser._parse_memory_dump(cleaned_item)
            if memory_dump:
                memory_dumps.append(memory_dump)
                if memory_dump.yara or memory_dump.cape_yara:
                    dumps_with_yara += 1
                if memory_dump.has_shellcode:
                    dumps_with_shellcode += 1
                total_extracted_pe += len(memory_dump.extracted_pe)
        
        return ProcmemoryData(
            memory_dumps=memory_dumps,
            total_dumps=len(memory_dumps),
            dumps_with_yara=dumps_with_yara,
            dumps_with_shellcode=dumps_with_shellcode,
            total_extracted_pe=total_extracted_pe
        )
    
    @staticmethod
    def _clean_memory_dump(data: Dict[str, Any]) -> Dict[str, Any]:
        """Clean memory dump by removing unwanted fields."""
        if not isinstance(data, dict):
            return data
        
        cleaned = data.copy()
        
        # COMPLETELY REMOVE address_space
        cleaned.pop("address_space", None)
        
        # Remove strings_path (not needed)
        cleaned.pop("strings_path", None)
        
        # Clean YARA hits - remove strings
        if "yara" in cleaned and isinstance(cleaned["yara"], list):
            cleaned_yara = []
            for yara in cleaned["yara"]:
                if isinstance(yara, dict):
                    # Remove strings from YARA
                    yara_copy = {k: v for k, v in yara.items() if k != "strings"}
                    cleaned_yara.append(yara_copy)
            cleaned["yara"] = cleaned_yara
        
        # Clean CAPE YARA hits - remove strings
        if "cape_yara" in cleaned and isinstance(cleaned["cape_yara"], list):
            cleaned_cape_yara = []
            for yara in cleaned["cape_yara"]:
                if isinstance(yara, dict):
                    # Remove strings from CAPE YARA
                    yara_copy = {k: v for k, v in yara.items() if k != "strings"}
                    cleaned_cape_yara.append(yara_copy)
            cleaned["cape_yara"] = cleaned_cape_yara
        
        # Clean extracted_pe files
        if "extracted_pe" in cleaned and isinstance(cleaned["extracted_pe"], list):
            cleaned_pe = []
            for pe in cleaned["extracted_pe"]:
                if isinstance(pe, dict):
                    # Remove unwanted fields from extracted PE
                    pe_copy = {k: v for k, v in pe.items() if k not in ["strings", "data", "dirents", "resources", "versioninfo", "icon"]}
                    
                    # Clean YARA in extracted PE
                    if "yara" in pe_copy and isinstance(pe_copy["yara"], list):
                        pe_yara_cleaned = []
                        for y in pe_copy["yara"]:
                            if isinstance(y, dict):
                                y_cleaned = {k: v for k, v in y.items() if k != "strings"}
                                pe_yara_cleaned.append(y_cleaned)
                        pe_copy["yara"] = pe_yara_cleaned
                    
                    if "cape_yara" in pe_copy and isinstance(pe_copy["cape_yara"], list):
                        pe_cape_yara_cleaned = []
                        for y in pe_copy["cape_yara"]:
                            if isinstance(y, dict):
                                y_cleaned = {k: v for k, v in y.items() if k != "strings"}
                                pe_cape_yara_cleaned.append(y_cleaned)
                        pe_copy["cape_yara"] = pe_cape_yara_cleaned
                    
                    cleaned_pe.append(pe_copy)
            cleaned["extracted_pe"] = cleaned_pe
        
        return cleaned
    
    @staticmethod
    def _parse_memory_dump(data: Dict[str, Any]) -> Optional[ProcessMemoryEntry]:
        """Parse a single memory dump from cleaned data."""
        if not data:
            return None
        
        # Parse YARA hits - keep only names and essential data
        yara_hits = []
        for yara in data.get("yara", [])[:_MAX_YARA_RULES_PER_FILE]:
            if isinstance(yara, dict):
                yara_hits.append(YaraHit(
                    name=yara.get("name", ""),
                    meta=yara.get("meta"),
                    addresses=yara.get("addresses"),
                    strings=None,  # EXCLUDED
                ))
        
        # Parse CAPE YARA hits
        cape_yara_hits = []
        for yara in data.get("cape_yara", [])[:_MAX_YARA_RULES_PER_FILE]:
            if isinstance(yara, dict):
                addresses = yara.get("addresses", {})
                if not isinstance(addresses, dict):
                    addresses = {}
                memblocks = yara.get("memblocks", {})
                if not isinstance(memblocks, dict):
                    memblocks = {}
                cape_yara_hits.append(MemoryYaraHit(
                    name=yara.get("name"),
                    rule=yara.get("rule"),
                    addresses=addresses,
                    memblocks=memblocks,
                    tags=yara.get("tags"),
                    meta=yara.get("meta"),
                ))
        
        # Parse extracted PEs from memory
        extracted_pe_list = []
        for pe in data.get("extracted_pe", [])[:_MAX_EXTRACTED_PE_PER_DUMP]:
            if isinstance(pe, dict):
                # Parse YARA for extracted PE - keep only names
                pe_yara_rules = []
                for y in pe.get("yara", []):
                    if isinstance(y, dict) and y.get("name"):
                        pe_yara_rules.append(y["name"])
                
                pe_cape_yara_rules = []
                for y in pe.get("cape_yara", []):
                    if isinstance(y, dict) and y.get("name"):
                        pe_cape_yara_rules.append(y["name"])
                
                extracted_pe_list.append(MemoryExtractedPE(
                    name=pe.get("name"),
                    path=pe.get("path"),
                    size=pe.get("size"),
                    type=pe.get("type")[:100] if pe.get("type") else None,
                    sha256=pe.get("sha256"),
                    md5=pe.get("md5"),
                    yara_rules=pe_yara_rules[:_MAX_YARA_RULES_PER_FILE],
                    cape_yara_rules=pe_cape_yara_rules[:_MAX_YARA_RULES_PER_FILE],
                    die=pe.get("die", [])[:5],
                ))
        
        # Detect shellcode/injection from YARA rule names
        has_shellcode = False
        has_injected_code = False
        for yara in yara_hits:
            name = yara.name.lower() if yara.name else ""
            if "shellcode" in name:
                has_shellcode = True
            if "inject" in name or "hollow" in name:
                has_injected_code = True
        
        for yara in cape_yara_hits:
            name = (yara.name or "").lower()
            if "shellcode" in name:
                has_shellcode = True
            if "inject" in name or "hollow" in name:
                has_injected_code = True
        
        pid_value = data.get("pid")
        if pid_value in (None, ""):
            pid_value = None
        else:
            try:
                pid_value = int(pid_value)
            except (TypeError, ValueError):
                pid_value = None

        return ProcessMemoryEntry(
            path=data.get("path"),
            sha256=data.get("sha256"),
            pid=pid_value,
            name=data.get("name"),
            proc_path=data.get("proc_path"),
            yara=yara_hits,
            cape_yara=cape_yara_hits,
            memory_regions=[],  # REMOVED
            total_regions=0,    # REMOVED
            executable_regions=0,  # REMOVED
            writable_regions=0,    # REMOVED
            strings_path=None,  # REMOVED
            extracted_pe=extracted_pe_list,
            has_shellcode=has_shellcode,
            has_injected_code=has_injected_code
        )
    
    @staticmethod
    def _generate_ai_summary(full: ProcessArtifactsResult) -> ProcessArtifactsAISummary:
        """Generate compact AI summary."""
        summary = ProcessArtifactsAISummary()
        
        # Overall stats
        summary.total_procdump_files = len(full.procdump.files)
        summary.total_dropped_files = len(full.dropped.files)
        summary.total_memory_dumps = len(full.procmemory.memory_dumps)
        
        # Procdump highlights
        summary.procdump_pe_count = full.procdump.total_pe_files
        
        # Extract malware families from procdump
        families = []
        processes = []
        for file in full.procdump.files:
            for rule in file.cape_yara_rules + file.yara_rules:
                if rule and rule not in families:
                    families.append(rule)
            if file.process_name and file.process_name not in processes:
                processes.append(file.process_name)
        summary.procdump_malware_families = families[:5]
        summary.procdump_processes = processes[:5]
        
        # Dropped highlights
        notable = []
        for file in full.dropped.files[:5]:
            if file.guest_paths:
                notable.append({
                    "name": file.name or "unknown",
                    "path": file.guest_paths[0][:80] if file.guest_paths else ""
                })
            elif "PE32" in str(file.type):
                notable.append({
                    "name": file.name or "unknown",
                    "type": (file.type or "PE file")[:50]
                })
        summary.dropped_notable_files = notable
        
        # Memory highlights
        summary.memory_dumps_with_yara = full.procmemory.dumps_with_yara
        summary.memory_dump_processes = [d.name for d in full.procmemory.memory_dumps[:5] if d.name]
        summary.memory_shellcode_detected = full.procmemory.dumps_with_shellcode > 0
        summary.memory_injection_detected = any(d.has_injected_code for d in full.procmemory.memory_dumps)
        summary.extracted_pe_from_memory_count = full.procmemory.total_extracted_pe
        
        # YARA summary
        all_yara_rules = []
        for file in full.procdump.files:
            all_yara_rules.extend(file.yara_rules)
            all_yara_rules.extend(file.cape_yara_rules)
        for file in full.dropped.files:
            all_yara_rules.extend(file.yara_rules)
            all_yara_rules.extend(file.cape_yara_rules)
        for dump in full.procmemory.memory_dumps:
            for yara in dump.yara:
                if yara.name:
                    all_yara_rules.append(yara.name)
            for yara in dump.cape_yara:
                if yara.name:
                    all_yara_rules.append(yara.name)
        
        summary.total_yara_hits = len(all_yara_rules)
        
        # Critical malware rules
        critical_patterns = ["XWorm", "NanoCore", "DCRat", "Quasar", "AsyncRAT", "VenomRAT"]
        critical_rules = []
        for rule in all_yara_rules:
            for pattern in critical_patterns:
                if pattern.lower() in rule.lower():
                    if rule not in critical_rules:
                        critical_rules.append(rule)
        summary.critical_malware_rules = critical_rules[:5]
        
        # Generate quick summary
        summary.generate_summary()
        
        return summary


# ============================================================
# Legacy/Compatibility Functions
# ============================================================

def extract_memory_data(report_path: Path) -> Dict[str, Any]:
    """Legacy: returns just the AI summary."""
    result = MemoryParser.parse(report_path)
    return result.get("ai_summary", {}) if result else {}


def clean_memory_data(memory_data: Dict[str, Any]) -> Dict[str, Any]:
    """Legacy compatibility."""
    return memory_data


def parse_memory_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Main entry point - returns {full, ai_summary}."""
    return MemoryParser.parse(report_path)


def process_memory_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Legacy alias."""
    return parse_memory_section(report_path)


# ============================================================
# Self-Execution
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        _logger.info("Usage: python memory_parser.py <cape_report.json>")
        sys.exit(1)
    
    report_file = Path(sys.argv[1])
    result = parse_memory_section(report_file)
    
    if result:
        print("\n" + "=" * 60)
        print("AI SUMMARY (What goes to LLM)")
        print("=" * 60)
        print(json.dumps(result.get("ai_summary", {}), indent=2))
        
        print("\n" + "=" * 60)
        print("FULL MODEL STATISTICS")
        print("=" * 60)
        full = result.get("full", {})
        
        procdump = full.get("procdump", {})
        dropped = full.get("dropped", {})
        procmemory = full.get("procmemory", {})
        
        print(f"Procdump files: {procdump.get('total_files', 0)}")
        print(f"  - PE files: {procdump.get('total_pe_files', 0)}")
        print(f"Dropped files: {dropped.get('total_files', 0)}")
        print(f"  - Suspicious paths: {len(dropped.get('suspicious_paths', []))}")
        print(f"Memory dumps: {procmemory.get('total_dumps', 0)}")
        print(f"  - With YARA: {procmemory.get('dumps_with_yara', 0)}")
        print(f"  - With shellcode: {procmemory.get('dumps_with_shellcode', 0)}")
        print(f"  - Extracted PEs: {procmemory.get('total_extracted_pe', 0)}")
        
        ai_summary = result.get("ai_summary", {})
        print(f"\nQuick Summary: {ai_summary.get('quick_summary', 'N/A')}")
    else:
        _logger.error("Failed to parse memory sections")
        sys.exit(1)