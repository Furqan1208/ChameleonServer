# D:\FYP\ChameleonServer\app\services\chunking_service.py
import json
from pathlib import Path
from typing import Dict, List, Any, Tuple
import math


class ChunkingService:
    """
    Service for chunking large analysis sections (behavior, strings) 
    into manageable pieces for AI processing.
    HANDLES: Parser output structure with metadata
    """
    
    def __init__(self):
        # Configuration for different section types - OPTIMIZED FOR REAL DATA
        self.chunk_config = {
            "behavior": {
                "chunk_size": 3,  # processes per chunk - optimized for real behavior data
                "chunk_by": "processes",  
                "max_tokens_estimate": 8000,
            },
            "strings": {
                "chunk_size": 2000,  # strings per chunk - optimized for real strings data
                "chunk_by": "strings",  
                "max_tokens_estimate": 6000,
            },
            "memory": {
                "chunk_size": 10,   # entries per chunk - optimized for real memory data
                "chunk_by": "entries",
                "max_tokens_estimate": 4000,
            }
        }
        
        # Token estimation factors (optimized for production)
        self.token_estimates = {
            "behavior_process": 120,   # processes are complex with API calls
            "behavior_api_call": 8,    # individual API calls are simpler
            "string_item": 3,        
            "memory_entry": 80,       # memory entries are complex with YARA, regions, etc.
        }

    def chunk_behavior_data(self, behavior_data: Dict[str, Any], chunk_size: int = None) -> List[Dict[str, Any]]:
        """
        Chunk behavior data by processes, ensuring each chunk is manageable for AI models.
        HANDLES: Both raw behavior data AND behavior parser output structure
        """
        # Handle behavior parser output structure - EXTRACT ACTUAL DATA
        actual_behavior_data = self._extract_behavior_data(behavior_data)
        
        if not actual_behavior_data or "processes" not in actual_behavior_data:
            # Return empty chunk structure for consistency
            return [{
                "data": actual_behavior_data or {}, 
                "chunk_info": {
                    "current_chunk": 1, 
                    "total_chunks": 1, 
                    "processes_in_chunk": 0,
                    "api_calls_in_chunk": 0,
                    "estimated_tokens": 0,
                    "chunk_size_config": self.chunk_config["behavior"]["chunk_size"]
                }
            }]
        
        config = self.chunk_config["behavior"]
        chunk_size = chunk_size or config["chunk_size"]
        processes = actual_behavior_data.get("processes", [])
        
        if not processes:
            return [{
                "data": actual_behavior_data, 
                "chunk_info": {
                    "current_chunk": 1, 
                    "total_chunks": 1, 
                    "processes_in_chunk": 0,
                    "api_calls_in_chunk": 0,
                    "estimated_tokens": 0,
                    "chunk_size_config": chunk_size
                }
            }]
        
        # Calculate total chunks needed
        total_chunks = math.ceil(len(processes) / chunk_size)
        
        chunks = []
        for chunk_idx in range(total_chunks):
            start_idx = chunk_idx * chunk_size
            end_idx = min((chunk_idx + 1) * chunk_size, len(processes))
            
            # Create chunk data
            chunk_processes = processes[start_idx:end_idx]
            
            # Count API calls in this chunk
            api_calls_in_chunk = sum(len(proc.get("calls", [])) for proc in chunk_processes)
            
            # Build chunk with original structure but only chunked processes
            chunk_data = {
                "processes": chunk_processes,
                # Include summary and other metadata for context
                "summary": actual_behavior_data.get("summary"),
                "anomaly": actual_behavior_data.get("anomaly", []),
                "processtree": self._get_relevant_processtree(actual_behavior_data.get("processtree", []), chunk_processes),
                "enhanced": actual_behavior_data.get("enhanced", []),
                "encryptedbuffers": actual_behavior_data.get("encryptedbuffers", [])
            }
            
            # Estimate token count for this chunk
            estimated_tokens = self._estimate_behavior_tokens(chunk_data)
            
            chunk_info = {
                "current_chunk": chunk_idx + 1,
                "total_chunks": total_chunks,
                "processes_in_chunk": len(chunk_processes),
                "api_calls_in_chunk": api_calls_in_chunk,
                "estimated_tokens": estimated_tokens,
                "chunk_size_config": chunk_size,
            }
            
            chunks.append({
                "data": chunk_data,
                "chunk_info": chunk_info
            })
        
        return chunks

    def chunk_strings_data(self, strings_data: Dict[str, Any], chunk_size: int = None) -> List[Dict[str, Any]]:
        """
        Chunk strings data by categories and string count.
        HANDLES: Strings parser output structure
        """
        # Handle strings parser output structure
        actual_strings_data = self._extract_strings_data(strings_data)
        
        if not actual_strings_data:
            return [{
                "data": actual_strings_data or {}, 
                "chunk_info": {
                    "current_chunk": 1, 
                    "total_chunks": 1, 
                    "strings_in_chunk": 0,
                    "estimated_tokens": 0,
                    "chunk_size_config": self.chunk_config["strings"]["chunk_size"]
                }
            }]
        
        config = self.chunk_config["strings"]
        chunk_size = chunk_size or config["chunk_size"]
        
        # Extract all strings from categories
        categories = actual_strings_data.get("categories", {})
        all_strings = []
        
        for category, strings in categories.items():
            all_strings.extend([(category, s) for s in strings])
        
        if not all_strings:
            return [{
                "data": actual_strings_data, 
                "chunk_info": {
                    "current_chunk": 1, 
                    "total_chunks": 1, 
                    "strings_in_chunk": 0,
                    "estimated_tokens": 0,
                    "chunk_size_config": chunk_size
                }
            }]
        
        total_chunks = math.ceil(len(all_strings) / chunk_size)
        chunks = []
        
        for chunk_idx in range(total_chunks):
            start_idx = chunk_idx * chunk_size
            end_idx = min((chunk_idx + 1) * chunk_size, len(all_strings))
            chunk_strings = all_strings[start_idx:end_idx]
            
            # Reorganize by category for this chunk
            chunk_categories = {}
            for category, string in chunk_strings:
                if category not in chunk_categories:
                    chunk_categories[category] = []
                chunk_categories[category].append(string)
            
            # Build chunk data
            chunk_data = {
                "categories": chunk_categories,
                "metadata": actual_strings_data.get("metadata", {})
            }
            
            # Estimate token count
            estimated_tokens = self._estimate_strings_tokens(chunk_data)
            
            chunk_info = {
                "current_chunk": chunk_idx + 1,
                "total_chunks": total_chunks,
                "strings_in_chunk": len(chunk_strings),
                "categories_in_chunk": list(chunk_categories.keys()),
                "estimated_tokens": estimated_tokens,
                "chunk_size_config": chunk_size,
            }
            
            chunks.append({
                "data": chunk_data,
                "chunk_info": chunk_info
            })
        
        return chunks

    def chunk_memory_data(self, memory_data: Dict[str, Any], chunk_size: int = None) -> List[Dict[str, Any]]:
        """
        Chunk memory data by process entries.
        HANDLES: Memory parser output structure
        """
        # Handle memory parser output structure
        actual_memory_data = self._extract_memory_data(memory_data)
            
        if not actual_memory_data or "procmemory" not in actual_memory_data:
            return [{
                "data": actual_memory_data or {}, 
                "chunk_info": {
                    "current_chunk": 1, 
                    "total_chunks": 1, 
                    "entries_in_chunk": 0,
                    "estimated_tokens": 0,
                    "chunk_size_config": self.chunk_config["memory"]["chunk_size"]
                }
            }]
        
        config = self.chunk_config["memory"]
        chunk_size = chunk_size or config["chunk_size"]
        procmemory = actual_memory_data.get("procmemory", [])
        
        if not procmemory:
            return [{
                "data": actual_memory_data, 
                "chunk_info": {
                    "current_chunk": 1, 
                    "total_chunks": 1, 
                    "entries_in_chunk": 0,
                    "estimated_tokens": 0,
                    "chunk_size_config": chunk_size
                }
            }]
        
        total_chunks = math.ceil(len(procmemory) / chunk_size)
        chunks = []
        
        for chunk_idx in range(total_chunks):
            start_idx = chunk_idx * chunk_size
            end_idx = min((chunk_idx + 1) * chunk_size, len(procmemory))
            
            chunk_entries = procmemory[start_idx:end_idx]
            
            chunk_data = {
                "procmemory": chunk_entries,
                "metadata": actual_memory_data.get("metadata", {})
            }
            
            # Estimate token count
            estimated_tokens = self._estimate_memory_tokens(chunk_data)
            
            chunk_info = {
                "current_chunk": chunk_idx + 1,
                "total_chunks": total_chunks,
                "entries_in_chunk": len(chunk_entries),
                "estimated_tokens": estimated_tokens,
                "chunk_size_config": chunk_size,
            }
            
            chunks.append({
                "data": chunk_data,
                "chunk_info": chunk_info
            })
        
        return chunks

    def _extract_behavior_data(self, behavior_data: Any) -> Dict[str, Any]:
        """
        Extract actual behavior data from parser output.
        HANDLES: Your behavior parser returns {"data": actual_data, "size_metrics": metadata}
        """
        if isinstance(behavior_data, dict):
            if "data" in behavior_data:
                # This is from behavior parser - return the actual data
                return behavior_data["data"]
            elif "processes" in behavior_data:
                # This is already the actual behavior data
                return behavior_data
        return behavior_data or {}

    def _extract_strings_data(self, strings_data: Any) -> Dict[str, Any]:
        """
        Extract actual strings data from parser output.
        """
        if isinstance(strings_data, dict):
            if "categories" in strings_data:
                # This is the actual strings data structure
                return strings_data
        return strings_data or {}

    def _extract_memory_data(self, memory_data: Any) -> Dict[str, Any]:
        """
        Extract actual memory data from parser output.
        """
        if isinstance(memory_data, dict):
            if "procmemory" in memory_data:
                # This is the actual memory data structure
                return memory_data
        return memory_data or {}

    def _get_relevant_processtree(self, processtree: List[Dict], chunk_processes: List[Dict]) -> List[Dict]:
        """
        Extract relevant parts of processtree for the current chunk.
        This helps maintain context without including the entire tree.
        """
        if not processtree or not chunk_processes:
            return []
        
        # Get PIDs from chunk processes
        chunk_pids = {str(proc.get("process_id")) for proc in chunk_processes}
        
        relevant_nodes = []
        
        def find_relevant_nodes(nodes: List[Dict], relevant_nodes: List[Dict]):
            for node in nodes:
                if str(node.get("pid")) in chunk_pids:
                    relevant_nodes.append(node)
                # Check children recursively
                if node.get("children"):
                    find_relevant_nodes(node["children"], relevant_nodes)
        
        find_relevant_nodes(processtree, relevant_nodes)
        return relevant_nodes

    def _estimate_behavior_tokens(self, behavior_chunk: Dict) -> int:
        """Estimate token count for behavior chunk"""
        estimated_tokens = 0
        
        # Processes
        for process in behavior_chunk.get("processes", []):
            estimated_tokens += self.token_estimates["behavior_process"]
            # API calls
            estimated_tokens += len(process.get("calls", [])) * self.token_estimates["behavior_api_call"]
        
        # Anomalies
        estimated_tokens += len(behavior_chunk.get("anomaly", [])) * 25
        
        # Processtree
        estimated_tokens += len(behavior_chunk.get("processtree", [])) * 40
        
        # Enhanced events
        estimated_tokens += len(behavior_chunk.get("enhanced", [])) * 30
        
        # Encrypted buffers
        estimated_tokens += len(behavior_chunk.get("encryptedbuffers", [])) * 20
        
        return estimated_tokens

    def _estimate_strings_tokens(self, strings_chunk: Dict) -> int:
        """Estimate token count for strings chunk"""
        estimated_tokens = 0
        
        for category, strings in strings_chunk.get("categories", {}).items():
            estimated_tokens += len(strings) * self.token_estimates["string_item"]
        
        return estimated_tokens

    def _estimate_memory_tokens(self, memory_chunk: Dict) -> int:
        """Estimate token count for memory chunk"""
        estimated_tokens = 0
        
        for entry in memory_chunk.get("procmemory", []):
            estimated_tokens += self.token_estimates["memory_entry"]
            # YARA rules
            estimated_tokens += len(entry.get("yara", [])) * 20
            estimated_tokens += len(entry.get("cape_yara", [])) * 20
            # Address space
            estimated_tokens += len(entry.get("address_space", [])) * 15
        
        return estimated_tokens

    def analyze_chunking_requirements(self, parsed_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze parsed results to determine chunking requirements for each section.
        HANDLES: Both raw data and parser output structures
        """
        analysis = {}
        
        for section_name, section_data in parsed_results.get("sections", {}).items():
            if section_name in self.chunk_config:
                config = self.chunk_config[section_name]
                
                if section_name == "behavior":
                    # Extract actual behavior data
                    actual_data = self._extract_behavior_data(section_data)
                    
                    process_count = len(actual_data.get("processes", []))
                    api_call_count = sum(len(proc.get("calls", [])) for proc in actual_data.get("processes", []))
                    chunks_needed = math.ceil(process_count / config["chunk_size"]) if process_count > 0 else 1
                    
                    analysis[section_name] = {
                        "needs_chunking": process_count > config["chunk_size"],
                        "process_count": process_count,
                        "api_call_count": api_call_count,
                        "estimated_chunks": chunks_needed,
                        "recommended_chunk_size": config["chunk_size"]
                    }
                
                elif section_name == "strings":
                    # Extract actual strings data
                    actual_data = self._extract_strings_data(section_data)
                    
                    total_strings = sum(len(strings) for strings in actual_data.get("categories", {}).values())
                    chunks_needed = math.ceil(total_strings / config["chunk_size"]) if total_strings > 0 else 1
                    
                    analysis[section_name] = {
                        "needs_chunking": total_strings > config["chunk_size"],
                        "total_strings": total_strings,
                        "category_count": len(actual_data.get("categories", {})),
                        "estimated_chunks": chunks_needed,
                        "recommended_chunk_size": config["chunk_size"]
                    }
                
                elif section_name == "memory":
                    # Extract actual memory data
                    actual_data = self._extract_memory_data(section_data)
                    
                    entry_count = len(actual_data.get("procmemory", []))
                    chunks_needed = math.ceil(entry_count / config["chunk_size"]) if entry_count > 0 else 1
                    
                    analysis[section_name] = {
                        "needs_chunking": entry_count > config["chunk_size"],
                        "entry_count": entry_count,
                        "estimated_chunks": chunks_needed,
                        "recommended_chunk_size": config["chunk_size"]
                    }
        
        return analysis


# Factory function for dependency injection
async def get_chunking_service():
    return ChunkingService()