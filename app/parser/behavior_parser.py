"""
Behavior Parser - Parses behavior section from CAPE report.
Output: { "full": {...}, "ai_summary": {...} }
"""

import json
import sys
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import Counter

from app.models.behaviorModel import (
    AnomalyEntry,
    BehaviorAISummary,
    BehaviorModel,
    CallArgument,
    CallEntry,
    CallCategoryStats,
    Environ,
    EnhancedEvent,
    EncryptedBufferEntry,
    FileActivities,
    HighValueCall,
    KeysSummary,
    Process,
    ProcessCallStats,
    SummaryModel,
    TreeNode,
)
from app.utils.logger import get_logger

_logger = get_logger("app.parser.behavior")

# Limits for AI summary
_MAX_PROCESSES = 20
_MAX_SUSPICIOUS_PROCESSES = 5
_MAX_FILES_PER_CATEGORY = 30
_MAX_EXECUTED_COMMANDS = 15
_MAX_RESOLVED_APIS = 20
_MAX_MUTEXES = 15
_MAX_SAMPLE_KEYS = 10
_MAX_HIGH_VALUE_CALLS = 5
_MAX_CALLS_FOR_STATS = 5000  # Limit for processing

# High-value API categories (keep details for these)
HIGH_VALUE_CATEGORIES = {
    "filesystem", "registry", "process", "injection", "network", "cryptography"
}

# Suspicious API patterns (for highlighting)
SUSPICIOUS_APIS = {
    "NtCreateFile", "NtWriteFile", "NtDeleteFile",
    "NtCreateKey", "NtSetValueKey", "NtDeleteKey",
    "NtCreateProcess", "NtCreateThread", "NtOpenProcess",
    "NtProtectVirtualMemory", "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
    "WSASend", "WSARecv", "connect", "send", "recv",
    "CryptEncrypt", "CryptDecrypt",
}


class BehaviorParser:
    """Parser for behavior section - produces full model + AI summary."""
    
    @staticmethod
    def parse(report_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse behavior section from report.
        Returns: { "full": {...}, "ai_summary": {...} }
        """
        try:
            raw_behavior = BehaviorParser._extract_raw_behavior(report_path)
            if not raw_behavior:
                return None
            
            full_result = BehaviorParser._parse_full_model(raw_behavior)
            ai_summary = BehaviorParser._generate_ai_summary(full_result)
            
            return {
                "full": full_result.model_dump(exclude_none=True),
                "ai_summary": ai_summary.model_dump(exclude_none=True)
            }
            
        except Exception as e:
            _logger.exception(f"Error parsing behavior section: {e}")
            return None
    
    @staticmethod
    def _extract_raw_behavior(report_path: Path) -> Optional[Dict[str, Any]]:
        """Extract raw behavior section from CAPE report."""
        try:
            with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            
            if isinstance(data, dict):
                return data.get("behavior", {})
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "behavior" in item:
                        return item["behavior"]
            return None
        except Exception as e:
            _logger.error(f"Error extracting behavior data: {e}")
            return None
    
    @staticmethod
    def _parse_full_model(raw_behavior: Dict[str, Any]) -> BehaviorModel:
        """Parse raw behavior data into complete model."""
        
        # Parse processes (with limited calls for full model)
        processes = []
        for proc in raw_behavior.get("processes", [])[:_MAX_PROCESSES]:
            # Parse calls with limit
            calls = []
            raw_calls = proc.get("calls", [])[:_MAX_CALLS_FOR_STATS]
            for call in raw_calls:
                if not isinstance(call, dict):
                    continue
                
                # Parse arguments
                arguments = []
                for arg in call.get("arguments", []):
                    if isinstance(arg, dict):
                        arguments.append(CallArgument(
                            name=arg.get("name", ""),
                            value=arg.get("value"),
                            pretty_value=arg.get("pretty_value"),
                        ))
                
                calls.append(CallEntry(
                    timestamp=call.get("timestamp", ""),
                    thread_id=call.get("thread_id", ""),
                    caller=call.get("caller", ""),
                    parentcaller=call.get("parentcaller", ""),
                    category=call.get("category", ""),
                    api=call.get("api", ""),
                    status=call.get("status", False),
                    return_=call.get("return"),
                    arguments=arguments,
                    repeated=call.get("repeated", 1),
                    pretty_return=call.get("pretty_return"),
                ))
            
            # Parse environ
            environ_list = []
            environ_data = proc.get("environ")
            if isinstance(environ_data, dict):
                environ_list.append(Environ(**environ_data))
            elif isinstance(environ_data, list):
                for env in environ_data[:5]:
                    if isinstance(env, dict):
                        environ_list.append(Environ(**env))
            
            # Parse file activities
            file_activities_data = proc.get("file_activities", {})
            file_activities = FileActivities(
                read_files=file_activities_data.get("read_files", [])[:50],
                write_files=file_activities_data.get("write_files", [])[:50],
                delete_files=file_activities_data.get("delete_files", [])[:50],
            )
            
            processes.append(Process(
                process_id=proc.get("process_id", 0),
                process_name=proc.get("process_name", ""),
                parent_id=proc.get("parent_id"),
                module_path=proc.get("module_path"),
                first_seen=proc.get("first_seen"),
                calls=calls,
                threads=proc.get("threads", [])[:20],
                environ=environ_list,
                file_activities=file_activities,
            ))
        
        # Parse anomalies
        anomalies = []
        for anomaly in raw_behavior.get("anomaly", []):
            if isinstance(anomaly, dict):
                anomalies.append(AnomalyEntry(
                    name=anomaly.get("name", ""),
                    pid=anomaly.get("pid", 0),
                    category=anomaly.get("category"),
                    funcname=anomaly.get("funcname"),
                    message=anomaly.get("message"),
                ))
        
        # Parse processtree (with children recursion)
        processtree = BehaviorParser._parse_processtree(raw_behavior.get("processtree", []))
        
        # Parse summary
        summary_data = raw_behavior.get("summary", {})
        summary = None
        if summary_data:
            summary = SummaryModel(
                files=summary_data.get("files", [])[:100],
                read_files=summary_data.get("read_files", [])[:100],
                write_files=summary_data.get("write_files", [])[:100],
                delete_files=summary_data.get("delete_files", [])[:50],
                keys=summary_data.get("keys", [])[:200],
                read_keys=summary_data.get("read_keys", [])[:200],
                write_keys=summary_data.get("write_keys", [])[:50],
                delete_keys=summary_data.get("delete_keys", [])[:50],
                executed_commands=summary_data.get("executed_commands", [])[:50],
                resolved_apis=summary_data.get("resolved_apis", [])[:50],
                mutexes=summary_data.get("mutexes", [])[:50],
                created_services=summary_data.get("created_services", [])[:20],
                started_services=summary_data.get("started_services", [])[:20],
            )
        
        # Parse enhanced events (limited)
        enhanced = []
        for event in raw_behavior.get("enhanced", [])[:100]:
            if isinstance(event, dict):
                enhanced.append(EnhancedEvent(
                    event=event.get("event", ""),
                    object=event.get("object", ""),
                    timestamp=event.get("timestamp", ""),
                    eid=event.get("eid", 0),
                    data=event.get("data", {}),
                ))
        
        # Parse encrypted buffers
        encryptedbuffers = []
        for buf in raw_behavior.get("encryptedbuffers", [])[:20]:
            if isinstance(buf, dict):
                encryptedbuffers.append(EncryptedBufferEntry(
                    process_name=buf.get("process_name", ""),
                    pid=buf.get("pid", 0),
                    api_call=buf.get("api_call", ""),
                    buffer=buf.get("buffer", "")[:200],
                    buffer_size=buf.get("buffer_size"),
                    crypt_key=buf.get("crypt_key"),
                ))
        
        return BehaviorModel(
            processes=processes,
            anomaly=anomalies,
            processtree=processtree,
            summary=summary,
            enhanced=enhanced,
            encryptedbuffers=encryptedbuffers,
        )
    
    @staticmethod
    def _parse_processtree(raw_tree: List[Dict], max_depth: int = 10) -> List[TreeNode]:
        """Parse process tree recursively."""
        if not raw_tree:
            return []
        
        trees = []
        for node in raw_tree[:max_depth]:
            if not isinstance(node, dict):
                continue
            
            # Parse children recursively
            children = BehaviorParser._parse_processtree(
                node.get("children", []), max_depth - 1
            )
            
            # Clean environ (keep only CommandLine and UserName for AI)
            environ = node.get("environ", {})
            if environ and isinstance(environ, dict):
                cleaned_environ = {}
                if "CommandLine" in environ:
                    cleaned_environ["CommandLine"] = environ["CommandLine"]
                if "UserName" in environ:
                    cleaned_environ["UserName"] = environ["UserName"]
                if not cleaned_environ:
                    cleaned_environ = None
            else:
                cleaned_environ = None
            
            trees.append(TreeNode(
                name=node.get("name", ""),
                pid=node.get("pid", 0),
                parent_id=node.get("parent_id"),
                module_path=node.get("module_path"),
                children=children,
                threads=None,  # EXCLUDED
                environ=cleaned_environ,
            ))
        
        return trees
    
    @staticmethod
    def _generate_ai_summary(full: BehaviorModel) -> BehaviorAISummary:
        """Generate compact AI summary from full model."""
        summary = BehaviorAISummary()
        
        # === Process Overview ===
        summary.total_processes = len(full.processes)
        
        # Identify suspicious processes (those that write files or execute commands)
        suspicious = []
        for proc in full.processes:
            susp_info = {
                "pid": proc.process_id,
                "name": proc.process_name,
            }
            # Add command line if available
            if proc.environ and proc.environ[0].CommandLine:
                susp_info["cmdline"] = proc.environ[0].CommandLine[:200]
            if proc.file_activities.write_files:
                susp_info["file_writes"] = len(proc.file_activities.write_files)
            if proc.file_activities.delete_files:
                susp_info["file_deletes"] = len(proc.file_activities.delete_files)
            suspicious.append(susp_info)
        
        summary.suspicious_processes = suspicious[:_MAX_SUSPICIOUS_PROCESSES]
        
        # === Process Tree ===
        summary.processtree = full.processtree
        
        # === API Call Statistics ===
        call_stats_list = []
        total_api_calls = 0
        
        for proc in full.processes:
            if not proc.calls:
                continue
            
            # Count calls by category
            category_counts = Counter()
            api_counts = Counter()
            high_value_calls = {}  # api -> list of details
            
            for call in proc.calls:
                category_counts[call.category] += 1
                api_counts[call.api] += 1
                total_api_calls += 1
                
                # Track high-value calls with details
                if call.api in SUSPICIOUS_APIS or call.category in HIGH_VALUE_CATEGORIES:
                    if call.api not in high_value_calls:
                        high_value_calls[call.api] = {"count": 0, "details": []}
                    high_value_calls[call.api]["count"] += 1
                    
                    # Extract details from arguments
                    for arg in call.arguments:
                        if arg.name in ["FileName", "FilePath"] and arg.value:
                            detail = f"{call.api}: {arg.value}"
                            if len(high_value_calls[call.api]["details"]) < 3:
                                high_value_calls[call.api]["details"].append(detail[:100])
                        elif arg.name == "KeyName" and arg.value:
                            detail = f"{call.api}: {arg.value}"
                            if len(high_value_calls[call.api]["details"]) < 3:
                                high_value_calls[call.api]["details"].append(detail[:100])
            
            # Build high value calls list
            high_value_list = []
            for api, data in sorted(high_value_calls.items(), key=lambda x: x[1]["count"], reverse=True)[:_MAX_HIGH_VALUE_CALLS]:
                high_value_list.append(HighValueCall(
                    api=api,
                    count=data["count"],
                    details=data["details"],
                ))
            
            call_stats_list.append(ProcessCallStats(
                process_id=proc.process_id,
                process_name=proc.process_name,
                total_calls=len(proc.calls),
                category_stats=dict(category_counts),
                unique_apis=list(api_counts.keys())[:20],
                high_value_calls=high_value_list,
            ))
        
        summary.call_stats = call_stats_list
        summary.total_api_calls = total_api_calls
        
        # === File Activity ===
        if full.summary:
            summary.files_accessed = full.summary.read_files[:_MAX_FILES_PER_CATEGORY]
            summary.files_written = full.summary.write_files[:_MAX_FILES_PER_CATEGORY]
            summary.files_deleted = full.summary.delete_files[:_MAX_FILES_PER_CATEGORY]
        
        # === Registry Activity (Aggregated) ===
        if full.summary:
            # Aggregate keys
            summary.keys_summary = BehaviorParser._aggregate_keys(full.summary.keys)
            summary.read_keys_summary = BehaviorParser._aggregate_keys(full.summary.read_keys)
            summary.write_keys = full.summary.write_keys[:_MAX_FILES_PER_CATEGORY]
            summary.delete_keys = full.summary.delete_keys[:_MAX_FILES_PER_CATEGORY]
        
        # === Command Execution ===
        if full.summary:
            summary.executed_commands = full.summary.executed_commands[:_MAX_EXECUTED_COMMANDS]
        
        # === API Resolution ===
        if full.summary:
            summary.resolved_apis = full.summary.resolved_apis[:_MAX_RESOLVED_APIS]
        
        # === Indicators ===
        if full.summary:
            summary.mutexes = full.summary.mutexes[:_MAX_MUTEXES]
            summary.created_services = full.summary.created_services
            summary.started_services = full.summary.started_services
        
        # === Anomalies ===
        summary.anomalies = full.anomaly
        
        # === Generate Quick Summary ===
        summary.generate_summary()
        
        return summary
    
    @staticmethod
    def _aggregate_keys(keys: List[str]) -> Optional[KeysSummary]:
        """Aggregate large key lists into summary."""
        if not keys:
            return None
        
        # Count total
        total_count = len(keys)
        
        # Extract unique hives
        hives = set()
        for key in keys[:500]:  # Sample for hives
            if key.startswith("HKLM"):
                hives.add("HKLM")
            elif key.startswith("HKCU"):
                hives.add("HKCU")
            elif key.startswith("HKCR"):
                hives.add("HKCR")
            elif key.startswith("HKU"):
                hives.add("HKU")
            elif key.startswith("HKCC"):
                hives.add("HKCC")
        
        # Take sample keys (first few, plus some unique ones)
        sample_keys = keys[:_MAX_SAMPLE_KEYS]
        
        # Add some unique keys if available
        if len(keys) > _MAX_SAMPLE_KEYS:
            # Try to add keys from different hives
            for hive in hives:
                for key in keys:
                    if key.startswith(hive) and key not in sample_keys:
                        sample_keys.append(key)
                        if len(sample_keys) >= _MAX_SAMPLE_KEYS:
                            break
                if len(sample_keys) >= _MAX_SAMPLE_KEYS:
                    break
        
        return KeysSummary(
            total_count=total_count,
            unique_hives=sorted(list(hives)),
            sample_keys=sample_keys[:_MAX_SAMPLE_KEYS],
        )


# ============================================================
# Legacy/Compatibility Functions
# ============================================================

def parse_behavior_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Main entry point - returns {full, ai_summary}."""
    return BehaviorParser.parse(report_path)


def process_behavior_section(report_path: Path) -> Optional[Dict[str, Any]]:
    """Legacy alias."""
    return parse_behavior_section(report_path)


# ============================================================
# Self-Execution
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        _logger.info("Usage: python behavior_parser.py <cape_report.json>")
        sys.exit(1)
    
    report_file = Path(sys.argv[1])
    result = parse_behavior_section(report_file)
    
    if result:
        print("\n" + "=" * 60)
        print("AI SUMMARY (What goes to LLM)")
        print("=" * 60)
        print(json.dumps(result.get("ai_summary", {}), indent=2))
        
        print("\n" + "=" * 60)
        print("FULL MODEL STATISTICS")
        print("=" * 60)
        full = result.get("full", {})
        
        print(f"Total processes: {len(full.get('processes', []))}")
        print(f"Anomalies: {len(full.get('anomaly', []))}")
        print(f"Process tree nodes: {len(full.get('processtree', []))}")
        print(f"Enhanced events: {len(full.get('enhanced', []))}")
        print(f"Encrypted buffers: {len(full.get('encryptedbuffers', []))}")
        
        if full.get("summary"):
            summary = full["summary"]
            print(f"Files: {len(summary.get('files', []))}")
            print(f"Registry keys: {len(summary.get('keys', []))}")
            print(f"Commands: {len(summary.get('executed_commands', []))}")
            print(f"Mutexes: {len(summary.get('mutexes', []))}")
        
        ai_summary = result.get("ai_summary", {})
        print(f"\nTotal API calls (stats): {ai_summary.get('total_api_calls', 0)}")
        print(f"Registry keys (aggregated): {ai_summary.get('keys_summary', {}).get('total_count', 0) if ai_summary.get('keys_summary') else 0}")
        print(f"\nQuick Summary: {ai_summary.get('quick_summary', 'N/A')}")
    else:
        _logger.error("Failed to parse behavior section")
        sys.exit(1)