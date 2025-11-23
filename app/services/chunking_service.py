# D:\FYP\ChameleonServer\app\services\chunking_service.py
import json
from pathlib import Path
from typing import Dict, List, Any, Tuple
import math


class ChunkingService:
    """
    Service for chunking large analysis sections (behavior, strings) 
    into manageable pieces for AI processing.
    """
    
    def __init__(self):
        # Configuration for different section types
        self.chunk_config = {
            "behavior": {
                "chunk_size": 1500,  # lines or processes per chunk
                "chunk_by": "processes",  # chunk by processes or lines
                "max_tokens_estimate": 8000,  # estimated tokens per chunk
            },
            "strings": {
                "chunk_size": 2000,  # strings per chunk
                "chunk_by": "strings",  # chunk by string count
                "max_tokens_estimate": 6000,
            },
            "memory": {
                "chunk_size": 500,  # memory entries per chunk
                "chunk_by": "entries",
                "max_tokens_estimate": 4000,
            }
        }
        
        # Token estimation factors (approximate)
        self.token_estimates = {
            "behavior_process": 50,  # tokens per process
            "behavior_api_call": 10,  # tokens per API call
            "string_item": 3,        # tokens per string
            "memory_entry": 20,      # tokens per memory entry
        }

    def chunk_behavior_data(self, behavior_data: Dict[str, Any], chunk_size: int = None) -> List[Dict[str, Any]]:
        """
        Chunk behavior data by processes, ensuring each chunk is manageable for AI models.
        
        Args:
            behavior_data: The parsed behavior section data
            chunk_size: Optional custom chunk size (uses config if None)
            
        Returns:
            List of behavior chunks with metadata
        """
        if not behavior_data or "processes" not in behavior_data:
            return [{"data": behavior_data, "chunk_info": {"current_chunk": 1, "total_chunks": 1, "processes_in_chunk": 0}}]
        
        config = self.chunk_config["behavior"]
        chunk_size = chunk_size or config["chunk_size"]
        processes = behavior_data.get("processes", [])
        
        if not processes:
            return [{"data": behavior_data, "chunk_info": {"current_chunk": 1, "total_chunks": 1, "processes_in_chunk": 0}}]
        
        # Calculate total chunks needed
        total_chunks = math.ceil(len(processes) / chunk_size)
        
        chunks = []
        for chunk_idx in range(total_chunks):
            start_idx = chunk_idx * chunk_size
            end_idx = min((chunk_idx + 1) * chunk_size, len(processes))
            
            # Create chunk data
            chunk_processes = processes[start_idx:end_idx]
            
            # Build chunk with original structure but only chunked processes
            chunk_data = {
                "processes": chunk_processes,
                # Include summary and other metadata for context
                "summary": behavior_data.get("summary"),
                "anomaly": behavior_data.get("anomaly", []),
                "processtree": self._get_relevant_processtree(behavior_data.get("processtree", []), chunk_processes),
            }
            
            # Estimate token count for this chunk
            estimated_tokens = self._estimate_behavior_tokens(chunk_data)
            
            chunk_info = {
                "current_chunk": chunk_idx + 1,
                "total_chunks": total_chunks,
                "processes_in_chunk": len(chunk_processes),
                "api_calls_in_chunk": sum(len(proc.get("calls", [])) for proc in chunk_processes),
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
        
        Args:
            strings_data: The parsed strings section data
            chunk_size: Optional custom chunk size
            
        Returns:
            List of strings chunks with metadata
        """
        if not strings_data:
            return [{"data": strings_data, "chunk_info": {"current_chunk": 1, "total_chunks": 1, "strings_in_chunk": 0}}]
        
        config = self.chunk_config["strings"]
        chunk_size = chunk_size or config["chunk_size"]
        
        # Extract all strings from categories
        categories = strings_data.get("categories", {})
        all_strings = []
        
        for category, strings in categories.items():
            all_strings.extend([(category, s) for s in strings])
        
        if not all_strings:
            return [{"data": strings_data, "chunk_info": {"current_chunk": 1, "total_chunks": 1, "strings_in_chunk": 0}}]
        
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
                "metadata": strings_data.get("metadata", {})
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
        
        Args:
            memory_data: The parsed memory section data
            chunk_size: Optional custom chunk size
            
        Returns:
            List of memory chunks with metadata
        """
        if not memory_data or "procmemory" not in memory_data:
            return [{"data": memory_data, "chunk_info": {"current_chunk": 1, "total_chunks": 1, "entries_in_chunk": 0}}]
        
        config = self.chunk_config["memory"]
        chunk_size = chunk_size or config["chunk_size"]
        procmemory = memory_data.get("procmemory", [])
        
        if not procmemory:
            return [{"data": memory_data, "chunk_info": {"current_chunk": 1, "total_chunks": 1, "entries_in_chunk": 0}}]
        
        total_chunks = math.ceil(len(procmemory) / chunk_size)
        chunks = []
        
        for chunk_idx in range(total_chunks):
            start_idx = chunk_idx * chunk_size
            end_idx = min((chunk_idx + 1) * chunk_size, len(procmemory))
            
            chunk_entries = procmemory[start_idx:end_idx]
            
            chunk_data = {
                "procmemory": chunk_entries,
                "metadata": memory_data.get("metadata", {})
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
        estimated_tokens += len(behavior_chunk.get("anomaly", [])) * 20
        
        # Processtree
        estimated_tokens += len(behavior_chunk.get("processtree", [])) * 30
        
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
            estimated_tokens += len(entry.get("yara", [])) * 15
            estimated_tokens += len(entry.get("cape_yara", [])) * 15
        
        return estimated_tokens

    def get_section_chunking_config(self, section_name: str) -> Dict[str, Any]:
        """Get chunking configuration for a specific section"""
        return self.chunk_config.get(section_name, {"chunk_size": 1000, "chunk_by": "items"})

    def update_chunk_size(self, section_name: str, new_size: int):
        """Update chunk size for a specific section"""
        if section_name in self.chunk_config:
            self.chunk_config[section_name]["chunk_size"] = new_size

    def analyze_chunking_requirements(self, parsed_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze parsed results to determine chunking requirements for each section.
        Useful for adaptive chunking based on actual data size.
        """
        analysis = {}
        
        for section_name, section_data in parsed_results.get("sections", {}).items():
            if section_name in self.chunk_config:
                config = self.chunk_config[section_name]
                
                if section_name == "behavior":
                    process_count = len(section_data.get("processes", []))
                    api_call_count = sum(len(proc.get("calls", [])) for proc in section_data.get("processes", []))
                    chunks_needed = math.ceil(process_count / config["chunk_size"])
                    
                    analysis[section_name] = {
                        "needs_chunking": process_count > config["chunk_size"],
                        "process_count": process_count,
                        "api_call_count": api_call_count,
                        "estimated_chunks": chunks_needed,
                        "recommended_chunk_size": config["chunk_size"]
                    }
                
                elif section_name == "strings":
                    total_strings = sum(len(strings) for strings in section_data.get("categories", {}).values())
                    chunks_needed = math.ceil(total_strings / config["chunk_size"])
                    
                    analysis[section_name] = {
                        "needs_chunking": total_strings > config["chunk_size"],
                        "total_strings": total_strings,
                        "category_count": len(section_data.get("categories", {})),
                        "estimated_chunks": chunks_needed,
                        "recommended_chunk_size": config["chunk_size"]
                    }
        
        return analysis


# Factory function for dependency injection
async def get_chunking_service():
    return ChunkingService()