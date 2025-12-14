# D:\FYP\ChameleonServer\app\services\simple_report_service.py
"""
Simple report service that saves each analysis in its own folder.
"""
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import uuid


class SimpleReportService:
    def __init__(self, base_dir: Path = Path("analysis_reports")):
        self.base_dir = base_dir
        self.base_dir.mkdir(exist_ok=True)
        self.metadata_file = base_dir / "metadata.json"
        self._init_metadata()
    
    def _init_metadata(self):
        """Initialize metadata file if it doesn't exist."""
        if not self.metadata_file.exists():
            self.save_metadata({"analyses": [], "count": 0})
    
    def load_metadata(self) -> Dict:
        """Load metadata from file."""
        try:
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        except:
            return {"analyses": [], "count": 0}
    
    def save_metadata(self, metadata: Dict):
        """Save metadata to file."""
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def create_analysis_folder(self, analysis_id: Optional[str] = None) -> Path:
        """Create folder for new analysis."""
        if not analysis_id:
            analysis_id = f"analysis_{uuid.uuid4().hex[:8]}"
        
        analysis_dir = self.base_dir / analysis_id
        analysis_dir.mkdir(exist_ok=True)
        return analysis_dir
    
    def save_cape_report(self, analysis_id: str, cape_report: Dict) -> Path:
        """Save raw CAPE report."""
        analysis_dir = self.base_dir / analysis_id
        analysis_dir.mkdir(exist_ok=True)
        
        file_path = analysis_dir / "cape_raw.json"
        with open(file_path, 'w') as f:
            json.dump(cape_report, f, indent=2)
        
        return file_path
    
    def save_parsed_report(self, analysis_id: str, parsed_data: Dict) -> Path:
        """Save parsed report."""
        analysis_dir = self.base_dir / analysis_id
        analysis_dir.mkdir(exist_ok=True)
        
        file_path = analysis_dir / "parsed.json"
        with open(file_path, 'w') as f:
            json.dump(parsed_data, f, indent=2)
        
        return file_path
    
    def save_ai_analysis(self, analysis_id: str, ai_analysis: Dict) -> Path:
        """Save AI analysis."""
        analysis_dir = self.base_dir / analysis_id
        analysis_dir.mkdir(exist_ok=True)
        
        file_path = analysis_dir / "ai_analysis.json"
        with open(file_path, 'w') as f:
            json.dump(ai_analysis, f, indent=2)
        
        return file_path
    
    def save_combined_report(self, analysis_id: str, **reports) -> Dict:
        """Save all reports and update metadata."""
        # Create analysis directory
        analysis_dir = self.create_analysis_folder(analysis_id)
        
        # Save individual reports
        saved_files = {}
        if "cape" in reports:
            saved_files["cape"] = self.save_cape_report(analysis_id, reports["cape"])
        if "parsed" in reports:
            saved_files["parsed"] = self.save_parsed_report(analysis_id, reports["parsed"])
        if "ai" in reports:
            saved_files["ai"] = self.save_ai_analysis(analysis_id, reports["ai"])
        
        # Update metadata
        metadata = self.load_metadata()
        
        analysis_meta = {
            "analysis_id": analysis_id,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "files": list(saved_files.keys()),
            "status": "completed"
        }
        
        # Add filename if provided
        if "filename" in reports:
            analysis_meta["filename"] = reports["filename"]
        
        # Add to metadata
        metadata["analyses"].append(analysis_meta)
        metadata["count"] = len(metadata["analyses"])
        self.save_metadata(metadata)
        
        return {
            "analysis_id": analysis_id,
            "directory": str(analysis_dir),
            "files": saved_files,
            "metadata": analysis_meta
        }
    
    def get_all_analyses(self) -> List[Dict]:
        """Get metadata for all analyses."""
        metadata = self.load_metadata()
        return metadata.get("analyses", [])
    
    def get_analysis(self, analysis_id: str) -> Optional[Dict]:
        """Get complete analysis data."""
        analysis_dir = self.base_dir / analysis_id
        
        if not analysis_dir.exists():
            return None
        
        result = {
            "analysis_id": analysis_id,
            "directory": str(analysis_dir)
        }
        
        # Load cape report if exists
        cape_file = analysis_dir / "cape_raw.json"
        if cape_file.exists():
            with open(cape_file, 'r') as f:
                result["cape_report"] = json.load(f)
        
        # Load parsed report if exists
        parsed_file = analysis_dir / "parsed.json"
        if parsed_file.exists():
            with open(parsed_file, 'r') as f:
                result["parsed_results"] = json.load(f)
        
        # Load AI analysis if exists
        ai_file = analysis_dir / "ai_analysis.json"
        if ai_file.exists():
            with open(ai_file, 'r') as f:
                result["ai_analysis"] = json.load(f)
        
        return result
    
    def delete_analysis(self, analysis_id: str) -> bool:
        """Delete an analysis."""
        analysis_dir = self.base_dir / analysis_id
        
        if analysis_dir.exists():
            # Remove directory
            shutil.rmtree(analysis_dir)
            
            # Update metadata
            metadata = self.load_metadata()
            metadata["analyses"] = [
                a for a in metadata["analyses"] 
                if a.get("analysis_id") != analysis_id
            ]
            metadata["count"] = len(metadata["analyses"])
            self.save_metadata(metadata)
            return True
        
        return False


# Create singleton instance
report_service = SimpleReportService()