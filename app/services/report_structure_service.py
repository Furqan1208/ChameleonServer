# D:\FYP\ChameleonServer\app\services\report_structure_service.py
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import uuid

class ReportStructureService:
    def __init__(self, base_dir: Path = Path("analysis_reports")):
        self.base_dir = base_dir
        self.base_dir.mkdir(exist_ok=True)
    
    def create_analysis_structure(self, analysis_id: str, filename: str) -> Dict[str, Path]:
        """Create folder structure for a new analysis"""
        analysis_dir = self.base_dir / analysis_id
        
        # Create all required directories
        dirs = {
            "root": analysis_dir,
            "cape": analysis_dir / "cape",
            "parsed": analysis_dir / "parsed",
            "parsed_individual": analysis_dir / "parsed" / "individual",
            "ai_analysis": analysis_dir / "ai_analysis",
            "ai_sections": analysis_dir / "ai_analysis" / "sections"
        }
        
        # Create directories
        for dir_path in dirs.values():
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Create metadata
        metadata = {
            "analysis_id": analysis_id,
            "filename": filename,
            "created_at": datetime.now().isoformat(),
            "status": "created",
            "components": {
                "cape": False,
                "parsed": False,
                "ai_analysis": False
            }
        }
        
        self.save_json(analysis_dir / "metadata.json", metadata)
        return dirs
    
    def save_cape_report(self, analysis_id: str, cape_data: Dict) -> Path:
        """Save raw CAPE report"""
        analysis_dir = self.base_dir / analysis_id
        cape_file = analysis_dir / "cape" / "raw_report.json"
        self.save_json(cape_file, cape_data)
        
        # Update metadata
        self._update_metadata(analysis_id, {"components.cape": True})
        return cape_file
    
    def save_parsed_report(self, analysis_id: str, parsed_data: Dict) -> Dict[str, Path]:
        """Save parsed report structure"""
        analysis_dir = self.base_dir / analysis_id
        parsed_dir = analysis_dir / "parsed"
        
        # Save combined
        combined_file = parsed_dir / "combined.json"
        self.save_json(combined_file, parsed_data)
        
        # Save individual sections
        sections = parsed_data.get("sections", {})
        individual_files = {}
        for section_name, section_data in sections.items():
            section_file = parsed_dir / "individual" / f"{section_name}.json"
            self.save_json(section_file, section_data)
            individual_files[section_name] = section_file
        
        # Update metadata
        self._update_metadata(analysis_id, {
            "components.parsed": True,
            "parsed_sections": list(sections.keys())
        })
        
        return {
            "combined": combined_file,
            "individual": individual_files
        }
    
    def save_ai_analysis(self, analysis_id: str, ai_data: Dict) -> Dict[str, Path]:
        """Save AI analysis structure"""
        analysis_dir = self.base_dir / analysis_id
        ai_dir = analysis_dir / "ai_analysis"
        
        # Save summary
        summary_file = ai_dir / "summary.json"
        summary = {
            "analysis_id": ai_data.get("analysis_id"),
            "timestamp": ai_data.get("timestamp"),
            "sections_analyzed": ai_data.get("sections_analyzed", []),
            "model_usage": ai_data.get("model_usage", {}),
            "duration_seconds": ai_data.get("duration_seconds", 0)
        }
        self.save_json(summary_file, summary)
        
        # Save sections
        sections_files = {}
        results = ai_data.get("results", {})
        for section_name, section_data in results.items():
            section_file = ai_dir / "sections" / f"{section_name}.json"
            self.save_json(section_file, section_data)
            sections_files[section_name] = section_file
        
        # Save model usage
        model_file = ai_dir / "model_usage.json"
        self.save_json(model_file, ai_data.get("model_usage", {}))
        
        # Update metadata
        self._update_metadata(analysis_id, {
            "components.ai_analysis": True,
            "ai_sections": list(results.keys())
        })
        
        return {
            "summary": summary_file,
            "sections": sections_files,
            "model_usage": model_file
        }
    
    def get_analysis(self, analysis_id: str) -> Optional[Dict]:
        """Get complete analysis structure"""
        analysis_dir = self.base_dir / analysis_id
        
        if not analysis_dir.exists():
            return None
        
        # Load metadata
        metadata_file = analysis_dir / "metadata.json"
        if not metadata_file.exists():
            return None
        
        metadata = self.load_json(metadata_file)
        
        # Load components based on availability
        result = {"metadata": metadata}
        
        if metadata.get("components", {}).get("cape", False):
            cape_file = analysis_dir / "cape" / "raw_report.json"
            if cape_file.exists():
                result["cape"] = self.load_json(cape_file)
        
        if metadata.get("components", {}).get("parsed", False):
            parsed_file = analysis_dir / "parsed" / "combined.json"
            if parsed_file.exists():
                result["parsed"] = self.load_json(parsed_file)
        
        if metadata.get("components", {}).get("ai_analysis", False):
            ai_summary_file = analysis_dir / "ai_analysis" / "summary.json"
            if ai_summary_file.exists():
                result["ai_analysis"] = self.load_json(ai_summary_file)
        
        return result
    
    def get_all_analyses(self) -> List[Dict]:
        """Get list of all analyses"""
        analyses = []
        
        for analysis_dir in self.base_dir.iterdir():
            if analysis_dir.is_dir():
                metadata_file = analysis_dir / "metadata.json"
                if metadata_file.exists():
                    metadata = self.load_json(metadata_file)
                    analyses.append(metadata)
        
        # Sort by creation date (newest first)
        analyses.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return analyses
    
    def delete_analysis(self, analysis_id: str) -> bool:
        """Delete an analysis"""
        analysis_dir = self.base_dir / analysis_id
        
        if analysis_dir.exists():
            shutil.rmtree(analysis_dir)
            return True
        return False
    
    def _update_metadata(self, analysis_id: str, updates: Dict):
        """Update metadata file"""
        metadata_file = self.base_dir / analysis_id / "metadata.json"
        
        if metadata_file.exists():
            metadata = self.load_json(metadata_file)
            
            # Handle nested updates (e.g., "components.cape": True)
            for key, value in updates.items():
                if "." in key:
                    parts = key.split(".")
                    current = metadata
                    for part in parts[:-1]:
                        current = current.setdefault(part, {})
                    current[parts[-1]] = value
                else:
                    metadata[key] = value
            
            # Update status based on components
            components = metadata.get("components", {})
            if all(components.values()):
                metadata["status"] = "complete"
            elif any(components.values()):
                metadata["status"] = "partial"
            
            self.save_json(metadata_file, metadata)
    
    @staticmethod
    def save_json(file_path: Path, data: Dict):
        """Save data to JSON file"""
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    
    @staticmethod
    def load_json(file_path: Path) -> Dict:
        """Load data from JSON file"""
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)


# Global instance
report_structure_service = ReportStructureService()