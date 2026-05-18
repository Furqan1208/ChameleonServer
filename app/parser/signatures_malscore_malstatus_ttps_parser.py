"""
Signatures Parser - Parses signatures, ttps, malscore, malstatus.
Output: { "full": {...}, "ai_summary": {...} }
Balanced approach: Keep critical IOCs, aggregate low-value data.
"""

import json
import sys
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from app.models.signaturesModel import (
    NewDataEntry,
    NewDataProcess,
    NewDataSign,
    Signature,
    SignatureCall,
    SignatureDataEntry,
    SignatureSection,
    SignaturesAISummary,
    SignaturesData,
    SignaturesProcessingResult,
    TTPSData,
    TTPSMapping,
)
from app.utils.logger import get_logger

_logger = get_logger("app.parser.signatures")

# AI Summary Limits (Balanced)
_MAX_HIGH_SEVERITY_SIGNATURES = 20   # Keep detailed for severity >= 3
_MAX_MEDIUM_SEVERITY_SIGNATURES = 10 # Keep limited details for severity == 2
_MAX_DOMAINS = 30                     # Keep all domains (critical for IOC)
_MAX_IPS = 30                         # Keep all IPs
_MAX_COMMANDS = 15                    # Keep most suspicious commands
_MAX_TTPS = 20                        # Keep top MITRE techniques
_MAX_PIDS = 30                        # Keep affected processes


class SignaturesParser:
    """Parser for signatures, ttps, malscore, malstatus sections."""
    
    # Severity thresholds
    HIGH_SEVERITY = 3
    MEDIUM_SEVERITY = 2
    LOW_SEVERITY = 1
    
    @staticmethod
    def parse(report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse signatures, ttps, malscore, malstatus from report.
        Returns: { "full": {...}, "ai_summary": {...} }
        """
        try:
            # Extract raw data
            raw_signatures = SignaturesParser._extract_section(report_path, "signatures")
            raw_ttps = SignaturesParser._extract_section(report_path, "ttps")
            raw_malscore = SignaturesParser._extract_malscore(report_path)
            raw_malstatus = SignaturesParser._extract_malstatus(report_path)
            
            # Parse full model (keeps everything for reference)
            signatures_data = SignaturesParser._parse_signatures_full(raw_signatures) if raw_signatures else SignaturesData()
            ttps_data = SignaturesParser._parse_ttps_full(raw_ttps) if raw_ttps else TTPSData()
            
            # Build full result (kept for reference, not sent to AI)
            full_result = SignaturesProcessingResult(
                signatures=signatures_data,
                ttps=ttps_data,
                malscore=raw_malscore or 0.0,
                malstatus=raw_malstatus or "unknown"
            )
            
            # Generate AI summary (balanced - keeps critical IOCs)
            ai_summary = SignaturesParser._generate_ai_summary(full_result)
            
            return {
                "full": full_result.model_dump(exclude_none=True),
                "ai_summary": ai_summary.model_dump(exclude_none=True)
            }
            
        except Exception as e:
            _logger.exception(f"Error parsing signatures section: {e}")
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
    def _extract_malscore(report_path: Path) -> Optional[float]:
        """Extract malscore from report."""
        try:
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                return data.get("malscore")
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "malscore" in item:
                        return item["malscore"]
            return None
        except Exception:
            return None
    
    @staticmethod
    def _extract_malstatus(report_path: Path) -> Optional[str]:
        """Extract malstatus from report."""
        try:
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                return data.get("malstatus")
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "malstatus" in item:
                        return item["malstatus"]
            return None
        except Exception:
            return None
    
    @staticmethod
    def _parse_signatures_full(raw_data: List[Dict[str, Any]]) -> SignaturesData:
        """Parse signatures section - keep ALL fields for full model."""
        signatures = []

        def _is_minimal_call_entry(data_item: Dict[str, Any]) -> bool:
            if not isinstance(data_item, dict):
                return False
            allowed_keys = {"type", "pid", "cid"}
            keys = {k for k, v in data_item.items() if v is not None}
            if not keys:
                return False
            if not keys.issubset(allowed_keys):
                return False
            if data_item.get("type") not in ("call", None):
                return False
            return True
        
        for item in raw_data:
            if not isinstance(item, dict):
                continue
            
            # Parse data array completely
            data_entries = []
            raw_data_items = item.get("data", []) if isinstance(item.get("data", []), list) else []
            raw_has_data = len(raw_data_items) > 0
            raw_all_minimal = raw_has_data and all(
                _is_minimal_call_entry(entry) for entry in raw_data_items if isinstance(entry, dict)
            )
            for data_item in item.get("data", []):
                if not isinstance(data_item, dict):
                    continue

                if _is_minimal_call_entry(data_item):
                    continue
                
                # Parse section if present
                section = None
                if "section" in data_item and isinstance(data_item["section"], dict):
                    sec = data_item["section"]
                    section = SignatureSection(
                        name=sec.get("name"),
                        raw_address=sec.get("raw_address"),
                        virtual_address=sec.get("virtual_address"),
                        virtual_size=sec.get("virtual_size"),
                        size_of_data=sec.get("size_of_data"),
                        characteristics=sec.get("characteristics"),
                        characteristics_raw=sec.get("characteristics_raw"),
                        entropy=sec.get("entropy"),
                    )
                
                data_entries.append(SignatureDataEntry(
                    type=data_item.get("type"),
                    pid=data_item.get("pid"),
                    cid=data_item.get("cid"),
                    domain=data_item.get("domain"),
                    IP=data_item.get("IP"),
                    command=data_item.get("command"),
                    self_read=data_item.get("self_read"),
                    file=data_item.get("file"),
                    value=data_item.get("value"),
                    section=section,
                    anomaly=data_item.get("anomaly"),
                    process=data_item.get("process"),
                    thread_resumed=data_item.get("thread_resumed"),
                ))
            
            # Parse new_data array
            new_data_entries = []
            for new_item in item.get("new_data", []):
                if not isinstance(new_item, dict):
                    continue
                
                process = None
                if "process" in new_item and isinstance(new_item["process"], dict):
                    proc = new_item["process"]
                    process = NewDataProcess(
                        process_name=proc.get("process_name"),
                        process_id=proc.get("process_id"),
                    )
                
                signs = []
                for sign in new_item.get("signs", []):
                    if isinstance(sign, dict):
                        signs.append(NewDataSign(
                            type=sign.get("type"),
                            value=sign.get("value"),
                        ))
                
                new_data_entries.append(NewDataEntry(
                    process=process,
                    signs=signs,
                ))

            if raw_has_data and raw_all_minimal and not new_data_entries:
                continue
            
            signatures.append(Signature(
                name=item.get("name", ""),
                description=item.get("description"),
                categories=item.get("categories", []),
                severity=item.get("severity"),
                weight=item.get("weight"),
                confidence=item.get("confidence"),
                references=item.get("references", []),
                data=data_entries,
                new_data=new_data_entries,
                families=item.get("families", []),
                alert=item.get("alert", False),
            ))
        
        return SignaturesData(signatures=signatures)
    
    @staticmethod
    def _parse_ttps_full(raw_data: List[Dict[str, Any]]) -> TTPSData:
        """Parse TTPS section - keep ALL fields."""
        mappings = []
        
        for item in raw_data:
            if not isinstance(item, dict):
                continue
            
            mappings.append(TTPSMapping(
                signature=item.get("signature", ""),
                ttps=item.get("ttps", []),
                mbcs=item.get("mbcs", []),
            ))
        
        return TTPSData(mappings=mappings)
    
    @staticmethod
    def _generate_ai_summary(full: SignaturesProcessingResult) -> SignaturesAISummary:
        """
        Generate AI summary - balanced approach:
        - Keep ALL domains, IPs, commands (critical IOCs)
        - Keep detailed high-severity signatures (severity >= 3)
        - Summarize medium/low severity signatures (just counts)
        """
        summary = SignaturesAISummary()
        
        # === Overall Assessment ===
        summary.malscore = full.malscore
        summary.malstatus = full.malstatus
        
        # === Collect IOCs (Keep ALL) ===
        domains: Set[str] = set()
        ips: Set[str] = set()
        commands: Set[str] = set()
        pids: Set[int] = set()
        categories_counts: Dict[str, int] = {}
        
        # === Track Capabilities ===
        capabilities = {
            "anti_debug": False,
            "anti_vm": False,
            "persistence": False,
            "injection": False,
            "info_stealer": False,
            "packing": False,
            "network": False,
        }
        
        # Counters
        total_sigs = 0
        critical_count = 0
        suspicious_count = 0
        low_count = 0
        
        # Store high-severity signatures for detailed output
        high_severity_details: List[Dict[str, Any]] = []
        medium_severity_details: List[Dict[str, Any]] = []
        
        for sig in full.signatures.signatures:
            total_sigs += 1
            severity = sig.severity or 0
            name_lower = sig.name.lower()
            
            # Severity counts
            if severity >= SignaturesParser.HIGH_SEVERITY:
                critical_count += 1
                # Keep detailed info for high-severity signatures
                high_severity_details.append(SignaturesParser._extract_signature_details(sig))
            elif severity == SignaturesParser.MEDIUM_SEVERITY:
                suspicious_count += 1
                # Keep limited info for medium severity
                if len(medium_severity_details) < _MAX_MEDIUM_SEVERITY_SIGNATURES:
                    medium_severity_details.append(SignaturesParser._extract_signature_details(sig, brief=True))
            elif severity == SignaturesParser.LOW_SEVERITY:
                low_count += 1
            
            # Categories
            for cat in sig.categories:
                categories_counts[cat] = categories_counts.get(cat, 0) + 1
            
            # Check capabilities
            if any(k in name_lower for k in ["debug", "antidebug"]):
                capabilities["anti_debug"] = True
            if any(k in name_lower for k in ["antivm", "anti-vm", "vm", "virtual"]):
                capabilities["anti_vm"] = True
            if any(k in name_lower for k in ["persistence", "autorun", "startup"]):
                capabilities["persistence"] = True
            if any(k in name_lower for k in ["inject", "hollow", "resumethread", "queueuserapc"]):
                capabilities["injection"] = True
            if any(k in name_lower for k in ["infostealer", "cookie", "credential", "password"]):
                capabilities["info_stealer"] = True
            if any(k in name_lower for k in ["packer", "entropy"]):
                capabilities["packing"] = True
            if any(k in name_lower for k in ["network", "connect", "http", "dns"]):
                capabilities["network"] = True
            
            # Extract IOCs from data (KEEP ALL)
            for data_entry in sig.data:
                # Domains
                if data_entry.domain:
                    domains.add(data_entry.domain)
                # IPs (extract from string if needed)
                if data_entry.IP:
                    ip_str = data_entry.IP
                    # Handle format like "104.21.87.11:443 (unknown)"
                    if ":" in ip_str:
                        ip_str = ip_str.split(":")[0]
                    # Remove parentheses and extra text
                    ip_str = re.sub(r'\s*\(.*\)$', '', ip_str)
                    ips.add(ip_str)
                # Commands (limit length but keep all)
                if data_entry.command:
                    cmd = data_entry.command[:250]  # Truncate long commands
                    commands.add(cmd)
                # PIDs
                if data_entry.pid:
                    pids.add(data_entry.pid)
            
            # Extract IOCs from new_data
            for new_entry in sig.new_data:
                if new_entry.process and new_entry.process.process_id:
                    pids.add(new_entry.process.process_id)
                for sign in new_entry.signs:
                    if sign.type == "file" and sign.value:
                        # Check for suspicious paths
                        pass
        
        # === Build AI Summary ===
        summary.total_signatures = total_sigs
        summary.critical_signatures = critical_count
        summary.suspicious_signatures = suspicious_count
        summary.low_severity_signatures = low_count
        
        # IOCs (KEEP ALL up to reasonable limits)
        summary.domains = list(domains)[:_MAX_DOMAINS]
        summary.ips = list(ips)[:_MAX_IPS]
        summary.commands = list(commands)[:_MAX_COMMANDS]
        summary.affected_pids = list(pids)[:_MAX_PIDS]
        summary.top_categories = dict(list(categories_counts.items())[:10])
        
        # Capabilities
        summary.has_anti_debug = capabilities["anti_debug"]
        summary.has_anti_vm = capabilities["anti_vm"]
        summary.has_persistence = capabilities["persistence"]
        summary.has_injection = capabilities["injection"]
        summary.has_info_stealer = capabilities["info_stealer"]
        summary.has_packing = capabilities["packing"]
        summary.has_network_activity = capabilities["network"]
        
        # High severity signatures (detailed)
        summary.high_severity_signatures = high_severity_details[:_MAX_HIGH_SEVERITY_SIGNATURES]
        
        # Medium severity signatures (brief)
        summary.medium_severity_signatures = medium_severity_details
        
        # Extract TTPs (KEEP ALL up to limit)
        all_ttps = set()
        for mapping in full.ttps.mappings:
            for ttp in mapping.ttps:
                all_ttps.add(ttp)
        summary.detected_ttps = list(all_ttps)[:_MAX_TTPS]
        
        # Generate quick summary
        summary.generate_summary()
        
        return summary
    
    @staticmethod
    def _extract_signature_details(sig: Signature, brief: bool = False) -> Dict[str, Any]:
        """Extract key details from a signature for AI summary."""
        details = {
            "name": sig.name,
            "severity": sig.severity,
            "categories": sig.categories[:3],  # Top 3 categories
        }
        
        if not brief:
            # For high-severity, include more details
            # Extract commands
            commands = []
            domains = []
            ips = []
            
            for data_entry in sig.data:
                if data_entry.command and len(commands) < 3:
                    commands.append(data_entry.command[:150])
                if data_entry.domain and len(domains) < 3:
                    domains.append(data_entry.domain)
                if data_entry.IP and len(ips) < 3:
                    ip_str = data_entry.IP.split(":")[0]
                    ips.append(ip_str)
            
            if commands:
                details["commands"] = commands
            if domains:
                details["domains"] = domains
            if ips:
                details["ips"] = ips
            
            # Check for injection
            if any(k in sig.name.lower() for k in ["inject", "hollow", "resumethread"]):
                details["injection_detected"] = True
        
        return details


# ============================================================
# Legacy/Compatibility Functions
# ============================================================

def extract_detection_data(report_path: Path) -> Dict[str, Any]:
    """Legacy: returns the signatures data."""
    result = SignaturesParser.parse(report_path)
    return result.get("full", {}).get("signatures", {}) if result else {}


def clean_detection_data(detection_data: Dict[str, Any]) -> Dict[str, Any]:
    """Legacy compatibility - returns AI summary."""
    if isinstance(detection_data, dict) and detection_data.get("_path"):
        result = SignaturesParser.parse(Path(detection_data["_path"]))
        return result.get("ai_summary", {}) if result else {}
    return {}


def parse_signatures_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Main entry point - returns {full, ai_summary}."""
    return SignaturesParser.parse(report_path)


def process_signatures_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Legacy alias."""
    return parse_signatures_section(report_path)


# ============================================================
# Self-Execution
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        _logger.info("Usage: python signatures_malscore_malstatus_ttps_parser.py <cape_report.json>")
        sys.exit(1)
    
    report_file = Path(sys.argv[1])
    result = parse_signatures_section(report_file)
    
    if result:
        print("\n" + "=" * 60)
        print("AI SUMMARY (What goes to LLM)")
        print("=" * 60)
        print(json.dumps(result.get("ai_summary", {}), indent=2))
        
        print("\n" + "=" * 60)
        print("FULL MODEL STATISTICS")
        print("=" * 60)
        full = result.get("full", {})
        signatures = full.get("signatures", {})
        ttps = full.get("ttps", {})
        
        print(f"Total signatures (full): {len(signatures.get('signatures', []))}")
        print(f"Total TTP mappings: {len(ttps.get('mappings', []))}")
        print(f"Malscore: {full.get('malscore', 0)}")
        print(f"Malstatus: {full.get('malstatus', 'unknown')}")
        
        ai_summary = result.get("ai_summary", {})
        print(f"\nDomains: {len(ai_summary.get('domains', []))}")
        print(f"IPs: {len(ai_summary.get('ips', []))}")
        print(f"Commands: {len(ai_summary.get('commands', []))}")
        print(f"High severity signatures: {len(ai_summary.get('high_severity_signatures', []))}")
        print(f"TTPs: {len(ai_summary.get('detected_ttps', []))}")
        print(f"\nQuick Summary: {ai_summary.get('quick_summary', 'N/A')}")
    else:
        _logger.error("Failed to parse signatures section")
        sys.exit(1)