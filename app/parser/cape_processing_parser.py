"""
CAPE Processing Parser - Extracts, validates, and creates AI summary.
Output: { "full": CAPEProcessingResult, "ai_summary": CAPEAISummary }
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.models.capeProcessingModel import (
    AssociatedHashes,
    CapeConfig,
    CAPEAISummary,
    CAPEPayloadsAndConfigs,
    CAPEProcessingResult,
    FileInfo,
    YaraHit,
)
from app.utils.logger import get_logger

_logger = get_logger("app.parser.cape_processing")

# Limits for AI summary
_MAX_FAMILIES = 5
_MAX_PAYLOAD_TYPES = 5
_MAX_INJECTION_PROCESSES = 5
_MAX_PAYLOAD_EXAMPLES = 3
_MAX_C2_SERVERS = 10
_MAX_CONFIG_INDICATORS = 10


class CAPEParser:
    """Parser for CAPE section - produces full model + AI summary."""
    
    @staticmethod
    def parse(report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse CAPE section from report.
        Returns: { "full": {...}, "ai_summary": {...} }
        """
        try:
            raw_cape = CAPEParser._extract_raw(report_path)
            if not raw_cape:
                return None
            
            full_result = CAPEParser._parse_full_model(raw_cape)
            ai_summary = CAPEParser._generate_ai_summary(full_result)
            
            return {
                "full": full_result.model_dump(exclude_none=True),
                "ai_summary": ai_summary.model_dump(exclude_none=True)
            }
            
        except Exception as e:
            _logger.exception(f"Error parsing CAPE section: {e}")
            return None
    
    @staticmethod
    def _extract_raw(report_path: Path) -> Dict[str, Any]:
        """Extract raw CAPE data from report."""
        try:
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                if "CAPE" in data:
                    return data["CAPE"]
                if "cape" in data:
                    return data["cape"]
                if "payloads" in data or "configs" in data:
                    return data
                return {}
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    if "CAPE" in item:
                        return item["CAPE"]
                    if "cape" in item:
                        return item["cape"]
                    if "payloads" in item or "configs" in item:
                        return item
                return {}
            return {}
        except Exception as e:
            _logger.error(f"Error extracting CAPE data: {e}")
            return {}
    
    @staticmethod
    def _parse_full_model(raw_cape: Dict[str, Any]) -> CAPEProcessingResult:
        """Parse raw CAPE data into complete model."""
        result = CAPEProcessingResult()
        
        # Parse payloads and configs from cape/cape root or direct payload list
        cape_data = raw_cape.get("cape", {})
        if not cape_data:
            cape_data = raw_cape.get("CAPE", {})
        if not cape_data and ("payloads" in raw_cape or "configs" in raw_cape):
            cape_data = raw_cape
        
        # Parse payloads (keep up to 50 for full model, but don't explode)
        payloads = cape_data.get("payloads", [])
        for payload in payloads[:100]:  # Limit to 100 for full model
            result.cape.payloads.append(CAPEParser._parse_file_info(payload))
        
        # Parse configs
        configs = cape_data.get("configs", [])
        for config in configs[:20]:  # Limit to 20 configs
            result.cape.configs.append(CAPEParser._parse_config(config))
        
        # Parse other categories
        result.dropped = [CAPEParser._parse_file_info(f) for f in raw_cape.get("dropped", [])[:50]]
        result.procdump = [CAPEParser._parse_file_info(f) for f in raw_cape.get("procdump", [])[:50]]
        result.package = [CAPEParser._parse_file_info(f) for f in raw_cape.get("package", [])[:50]]
        result.CAPE_path = [CAPEParser._parse_file_info(f) for f in raw_cape.get("CAPE_path", [])[:50]]
        
        # Parse detections (KEEP FULL - important for AI)
        result.detections = raw_cape.get("detections", [])
        result.detections2pid = raw_cape.get("detections2pid", {})
        
        # Parse pefiles
        result.pefiles = raw_cape.get("pefiles", {})
        
        return result
    
    @staticmethod
    def _parse_file_info(data: Dict[str, Any]) -> FileInfo:
        """Parse FileInfo from raw data."""
        guest_paths = data.get("guest_paths")
        if isinstance(guest_paths, str):
            guest_paths = [guest_paths]
        elif guest_paths is None:
            guest_paths = None
        elif not isinstance(guest_paths, list):
            guest_paths = [str(guest_paths)]

        return FileInfo(
            name=data.get("name"),
            path=data.get("path"),
            size=data.get("size"),
            type=data.get("type"),
            md5=data.get("md5"),
            sha1=data.get("sha1"),
            sha256=data.get("sha256"),
            sha512=data.get("sha512"),
            sha3_384=data.get("sha3_384"),
            crc32=data.get("crc32"),
            ssdeep=data.get("ssdeep"),
            tlsh=data.get("tlsh"),
            rh_hash=data.get("rh_hash"),
            cape_type=data.get("cape_type"),
            cape_type_code=data.get("cape_type_code"),
            process_name=data.get("process_name"),
            process_path=data.get("process_path"),
            module_path=data.get("module_path"),
            pid=data.get("pid"),
            virtual_address=data.get("virtual_address"),
            guest_paths=guest_paths,
            yara=[YaraHit(**y) for y in data.get("yara", []) if isinstance(y, dict)][:5],
            cape_yara=[YaraHit(**y) for y in data.get("cape_yara", []) if isinstance(y, dict)][:5],
            clamav=data.get("clamav", [])[:5],
            pe=data.get("pe"),
            selfextract=data.get("selfextract"),
            strings=data.get("strings", [])[:10] if data.get("strings") else None,
            die=data.get("die"),
            data=data.get("data"),
        )
    
    @staticmethod
    def _parse_config(data: Dict[str, Any]) -> CapeConfig:
        """Parse CapeConfig from raw data."""
        family = None
        config_data = {}
        
        for key, value in data.items():
            if key.startswith("_"):
                continue
            family = key
            config_data = value if isinstance(value, dict) else {key: value}
            break
        
        # Parse associated hashes
        assoc_config_hashes = []
        for h in data.get("_associated_config_hashes", []):
            if isinstance(h, dict):
                assoc_config_hashes.append(AssociatedHashes(
                    md5=h.get("md5"),
                    sha1=h.get("sha1"),
                    sha256=h.get("sha256"),
                    sha512=h.get("sha512"),
                    sha3_384=h.get("sha3_384"),
                ))
        
        assoc_analysis_hashes = None
        if data.get("_associated_analysis_hashes"):
            ah = data["_associated_analysis_hashes"]
            assoc_analysis_hashes = AssociatedHashes(
                md5=ah.get("md5"),
                sha1=ah.get("sha1"),
                sha256=ah.get("sha256"),
                sha512=ah.get("sha512"),
                sha3_384=ah.get("sha3_384"),
            )
        
        return CapeConfig(
            family=family,
            config_data=config_data,
            associated_config_hashes=assoc_config_hashes,
            associated_analysis_hashes=assoc_analysis_hashes,
        )
    
    @staticmethod
    def _generate_ai_summary(full: CAPEProcessingResult) -> CAPEAISummary:
        """Generate compact AI summary from full model."""
        summary = CAPEAISummary()
        
        # Extract families from configs
        families = []
        for config in full.cape.configs:
            if config.family and config.family not in families:
                families.append(config.family)
        
        # Extract families from detections
        for detection in full.detections:
            if isinstance(detection, dict):
                family = detection.get("family")
                if family and family not in families:
                    families.append(family)
        
        summary.detected_families = families[:_MAX_FAMILIES]
        
        # Count payloads by type
        all_payloads = (full.cape.payloads + full.dropped + 
                        full.procdump + full.package + full.CAPE_path)
        summary.total_payloads = len(all_payloads)
        
        # Payload types
        type_counts = {}
        for payload in all_payloads:
            cape_type = payload.cape_type or "Unknown"
            if "Shellcode" in cape_type:
                type_name = "Shellcode"
            elif "DLL" in cape_type:
                type_name = "PE DLL"
            elif "PE" in cape_type or "executable" in str(payload.type):
                type_name = "PE Executable"
            else:
                type_name = "Other"
            type_counts[type_name] = type_counts.get(type_name, 0) + 1
        
        sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        summary.payload_types = dict(sorted_types[:_MAX_PAYLOAD_TYPES])
        
        # Process injection analysis
        process_payload_counts = {}
        process_info = {}
        
        for payload in all_payloads:
            proc_name = payload.process_name
            pid = payload.pid
            if proc_name:
                key = f"{proc_name}|{pid}" if pid else proc_name
                if key not in process_payload_counts:
                    process_payload_counts[key] = 0
                    process_info[key] = {"process": proc_name, "pid": pid}
                process_payload_counts[key] += 1
        
        sorted_processes = sorted(process_payload_counts.items(), key=lambda x: x[1], reverse=True)
        for key, count in sorted_processes[:_MAX_INJECTION_PROCESSES]:
            info = process_info[key]
            summary.injection_processes.append({
                "process": info["process"],
                "pid": info["pid"],
                "payload_count": count
            })
        
        # Payload examples (first 2-3)
        for payload in all_payloads[:_MAX_PAYLOAD_EXAMPLES]:
            example = {
                "cape_type": payload.cape_type or "Unknown",
                "process": payload.process_name,
                "size": payload.size,
            }
            if payload.virtual_address:
                example["virtual_address"] = payload.virtual_address
            if payload.type:
                example["file_type"] = payload.type[:60]
            summary.payload_examples.append(example)
        
        # Config summary
        summary.total_configs = len(full.cape.configs)
        summary.has_valid_configs = len(full.cape.configs) > 0
        summary.has_malware_config = len(full.cape.configs) > 0 or len(full.detections) > 0
        
        # Extract C2 servers from configs
        c2_servers = CAPEParser._extract_c2_servers(full.cape.configs)
        summary.c2_servers = c2_servers[:_MAX_C2_SERVERS]
        
        # Extract key config indicators
        config_indicators = {}
        important_keys = ["Mutex", "Install", "InstallFolder", "InstallFile", "Version", 
                          "Group", "RunOnStartup", "Persistence", "Key", "Certificate",
                          "Hosts", "Ports", "Sleep", "BSOD", "Mutex", "Campaign"]
        
        for config in full.cape.configs:
            if config.config_data:
                for key, value in config.config_data.items():
                    if key in important_keys and key not in config_indicators:
                        if isinstance(value, list) and value:
                            config_indicators[key] = value[0] if len(value) == 1 else value[:3]
                        elif value:
                            config_indicators[key] = value
                        
                        if len(config_indicators) >= _MAX_CONFIG_INDICATORS:
                            break
            if len(config_indicators) >= _MAX_CONFIG_INDICATORS:
                break
        
        summary.config_indicators = config_indicators
        
        # Process family mappings from detections2pid (KEEP FULL - important)
        summary.process_family_mappings = full.detections2pid
        
        # Has dropped files
        summary.has_dropped_files = len(full.dropped) > 0 or len(full.cape.payloads) > 0
        
        # Determine primary injection method
        if summary.payload_types.get("Shellcode", 0) > 0:
            summary.primary_injection_method = "Shellcode injection"
        elif len(summary.injection_processes) > 1:
            summary.primary_injection_method = "Process injection"
        else:
            summary.primary_injection_method = "Direct execution"
        
        # Generate quick summary
        summary.generate_summary()
        
        return summary
    
    @staticmethod
    def _extract_c2_servers(configs: List[CapeConfig]) -> List[str]:
        """Extract C2 server strings from configs."""
        c2_servers = []
        c2_fields = ["Hosts", "Host", "PrimaryConnectionHost", "BackupConnectionHost", 
                     "cncs", "C2", "Server", "Address"]
        port_fields = ["Ports", "Port", "ConnectionPort"]
        
        for config in configs:
            if not config.config_data:
                continue
            
            # Get hosts
            hosts = []
            for field in c2_fields:
                if field in config.config_data:
                    value = config.config_data[field]
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, list):
                                for subitem in item:
                                    if isinstance(subitem, str):
                                        hosts.append(subitem)
                            elif isinstance(item, str):
                                hosts.append(item)
                    elif isinstance(value, str):
                        hosts.append(value)
            
            # Get ports
            ports = []
            for field in port_fields:
                if field in config.config_data:
                    value = config.config_data[field]
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, list):
                                for subitem in item:
                                    ports.append(str(subitem))
                            else:
                                ports.append(str(item))
                    else:
                        ports.append(str(value))
            
            # Combine
            default_port = ports[0] if ports else None
            for host in hosts[:5]:
                if ":" in host and not any(c.isalpha() for c in host.split(":")[0]):
                    c2_servers.append(host)
                elif default_port:
                    c2_servers.append(f"{host}:{default_port}")
                else:
                    c2_servers.append(host)
        
        # Remove duplicates
        seen = set()
        unique = []
        for server in c2_servers:
            if server not in seen:
                seen.add(server)
                unique.append(server)
        
        return unique


# ============================================================
# Legacy/Compatibility Functions
# ============================================================

def extract_cape_data(report_path: Path) -> Dict[str, Any]:
    """Legacy: returns just the AI summary."""
    result = CAPEParser.parse(report_path)
    return result.get("ai_summary", {}) if result else {}


def filter_payloads(cape_data: Dict[str, Any]) -> Dict[str, Any]:
    """Legacy compatibility."""
    return cape_data


def process_cape_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Process CAPE section and return full result."""
    return CAPEParser.parse(report_path)


def parse_cape_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Main entry point - returns {full, ai_summary}."""
    return CAPEParser.parse(report_path)


# ============================================================
# Self-Execution
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        _logger.info("Usage: python cape_processing_parser.py <cape_report.json>")
        sys.exit(1)
    
    report_file = Path(sys.argv[1])
    result = parse_cape_section(report_file)
    
    if result:
        print("\n" + "=" * 60)
        print("AI SUMMARY (What goes to LLM)")
        print("=" * 60)
        print(json.dumps(result.get("ai_summary", {}), indent=2))
        
        print("\n" + "=" * 60)
        print("FULL MODEL STATISTICS")
        print("=" * 60)
        full = result.get("full", {})
        cape = full.get("cape", {})
        print(f"Total payloads: {len(cape.get('payloads', []))}")
        print(f"Total configs: {len(cape.get('configs', []))}")
        print(f"Dropped files: {len(full.get('dropped', []))}")
        print(f"Detections: {len(full.get('detections', []))}")
        print(f"detections2pid: {len(full.get('detections2pid', {}))} PIDs")
    else:
        _logger.error("Failed to parse CAPE section")