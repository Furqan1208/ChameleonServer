from typing import Any, Dict, List


class DataExtractor:
    @staticmethod
    def extract_behavior_data(data: Any) -> Dict[str, Any]:
        if not isinstance(data, dict):
            return {}

        if "data" in data:
            return data["data"]

        if "processes" in data:
            return data

        return {}

    @staticmethod
    def extract_strings_data(data: Any) -> Dict[str, Any]:
        if isinstance(data, dict) and "categories" in data:
            return data
        return {}

    @staticmethod
    def extract_memory_data(data: Any) -> Dict[str, Any]:
        if isinstance(data, dict) and "procmemory" in data:
            return data
        return {}

    @staticmethod
    def filter_processtree(processtree: List[Dict], target_pids: set) -> List[Dict]:
        if not processtree or not target_pids:
            return []

        relevant_nodes = []

        def traverse(nodes: List[Dict]) -> None:
            for node in nodes:
                if str(node.get("pid")) in target_pids:
                    relevant_nodes.append(node)

                if node.get("children"):
                    traverse(node["children"])

        traverse(processtree)
        return relevant_nodes
