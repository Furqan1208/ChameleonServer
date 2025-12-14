# D:\FYP\ChameleonServer\app\controllers\analysis_routes.py
import json
import uuid
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.database.mongodb import get_database
from app.services.ai_analysis_service import AIAnalysisService
from app.services.cape_analysis_service import CapeAnalysisService
from app.services.chunking_service import ChunkingService
from app.services.model_service import ModelService
from app.services.parser_service import ParserService
from app.services.report_structure_service import report_structure_service

router = APIRouter(
    prefix="/analysis",
    tags=["analysis"],
    responses={404: {"description": "Not found"}},
)


async def get_database_dep(db: AsyncIOMotorDatabase = Depends(get_database)):
    """Get database connection."""
    return db


async def get_analysis_service(db: AsyncIOMotorDatabase = Depends(get_database_dep)):
    """Get CAPE analysis service."""
    return CapeAnalysisService(db)


async def get_model_service():
    """Get AI model service with parallel support."""
    return ModelService()


async def get_parser_service():
    """Get CAPE report parser service."""
    return ParserService(models_dir=Path("app/parser"))


async def get_chunking_service():
    """Get chunking service for large sections."""
    return ChunkingService()


async def get_ai_analysis_service(
    model_service: ModelService = Depends(get_model_service),
    parser_service: ParserService = Depends(get_parser_service),
    chunking_service: ChunkingService = Depends(get_chunking_service),
):
    """Get AI analysis service with parallel processing."""
    return AIAnalysisService(model_service, parser_service, chunking_service)


def calculate_malscore(parsed_results: dict, ai_analysis: dict) -> float:
    """
    Calculate a simple malware score for demonstration.
    """
    score = 0.0
    
    # Add score based on signatures
    if "signatures" in parsed_results.get("sections", {}):
        sigs = parsed_results["sections"]["signatures"]
        if isinstance(sigs, dict) and "signatures" in sigs:
            score += len(sigs["signatures"]) * 0.5
    
    # Add score based on AI analysis
    if "results" in ai_analysis and "final_synthesis" in ai_analysis["results"]:
        synthesis = ai_analysis["results"]["final_synthesis"]
        if isinstance(synthesis, str):
            if "malicious" in synthesis.lower():
                score += 3.0
            if "suspicious" in synthesis.lower():
                score += 2.0
    
    # Cap at 10
    return min(10.0, score)


@router.post("/complete", status_code=status.HTTP_201_CREATED)
async def complete_analysis(
    file: UploadFile = File(...),
    model_name: Optional[str] = "gemini-2.5-flash",
    enable_parallel: bool = True,
    max_parallel_sections: int = 4,
    analysis_service: CapeAnalysisService = Depends(get_analysis_service),
    parser_service: ParserService = Depends(get_parser_service),
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service),
):
    """
    Complete malware analysis: File → CAPE → Parse → AI
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []
    
    try:
        print(f"\n{'=' * 70}")
        print("🎯 Starting COMPLETE Analysis")
        print(f"{'=' * 70}")
        print(f"File: {file.filename}")
        print(f"Analysis ID: {analysis_id}")
        print(f"AI Model: {model_name}")
        print(f"Parallel Mode: {'Enabled' if enable_parallel else 'Disabled'}")
        print(f"{'=' * 70}\n")
        
        # Create folder structure
        structure = report_structure_service.create_analysis_structure(analysis_id, file.filename)
        
        # 1. CAPE Analysis
        print("📊 STEP 1: CAPE Sandbox Analysis...")
        print("-" * 70)
        cape_report = await analysis_service.upload_and_analyze(file)
        
        if not cape_report:
            raise HTTPException(500, "CAPE analysis failed - no report returned")
        
        report_structure_service.save_cape_report(analysis_id, cape_report)
        print("✅ CAPE analysis saved")
        
        # Save CAPE report temporarily for parsing
        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as temp_file:
            json.dump(cape_report, temp_file, indent=2)
            temp_file_path = Path(temp_file.name)
            temp_files.append(temp_file_path)
            
        # 2. Parse CAPE Report
        print("\n🔧 STEP 2: Parsing CAPE Report...")
        print("-" * 70)
        parsed_results = parser_service.parse_complete_report(
            temp_file_path, 
            structure["parsed"]
        )
        
        # Save parsed results
        parsed_files = report_structure_service.save_parsed_report(analysis_id, parsed_results)
        sections_parsed = parsed_results["metadata"]["sections_parsed"]
        print(f"✅ Parsed {len(sections_parsed)} sections: {', '.join(sections_parsed)}")
        
        # 3. AI Analysis
        print("\n🤖 STEP 3: AI Analysis...")
        print("-" * 70)
        ai_analysis_result = await ai_analysis_service.analyze(
            parsed_results=parsed_results,
            model_name=model_name,
            enable_parallel=enable_parallel,
            max_parallel_sections=max_parallel_sections,
        )
        
        # Save AI analysis
        ai_files = report_structure_service.save_ai_analysis(analysis_id, ai_analysis_result)
        print(f"✅ AI analysis of {len(ai_analysis_result.get('sections_analyzed', []))} sections completed")
        
        # Calculate malscore
        malscore = calculate_malscore(parsed_results, ai_analysis_result)
        
        # Update metadata with final status
        report_structure_service._update_metadata(analysis_id, {
            "status": "complete",
            "malscore": malscore,
            "analysis_type": "complete",
            "model_used": model_name,
            "completed_at": datetime.now().isoformat(),
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_analysis_result.get("sections_analyzed", [])
        })
        
        print(f"\n{'=' * 70}")
        print("🎉 Analysis COMPLETE!")
        print(f"{'=' * 70}")
        print(f"Analysis ID: {analysis_id}")
        print(f"Threat Score: {malscore:.1f}/10")
        print(f"Report Path: {structure['root']}")
        print(f"{'=' * 70}\n")
        
        return {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "status": "complete",
            "message": "Complete analysis finished successfully",
            "components": ["cape", "parsed", "ai_analysis"],
            "malscore": malscore,
            "created_at": datetime.now().isoformat(),
            "report_path": str(structure["root"]),
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_analysis_result.get("sections_analyzed", [])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ Analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Analysis failed: {str(e)}")
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass


@router.post("/parse-only", status_code=status.HTTP_201_CREATED)
async def parse_only_analysis(
    file: UploadFile = File(...),
    parser_service: ParserService = Depends(get_parser_service),
):
    """
    Parse existing CAPE report only (no AI)
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []
    
    try:
        if not file.filename or not file.filename.lower().endswith('.json'):
            raise HTTPException(400, "Only JSON files are supported for parsing")
        
        print(f"\n{'=' * 70}")
        print("📄 Starting PARSE-ONLY Analysis")
        print(f"{'=' * 70}")
        print(f"File: {file.filename}")
        print(f"Analysis ID: {analysis_id}")
        print(f"{'=' * 70}\n")
        
        # Create folder structure
        structure = report_structure_service.create_analysis_structure(analysis_id, file.filename)
        
        # Save uploaded CAPE report temporarily
        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = Path(temp_file.name)
            temp_files.append(temp_file_path)
        
        # Load and save CAPE data
        with open(temp_file_path, "r", encoding="utf-8") as f:
            cape_data = json.load(f)
        
        report_structure_service.save_cape_report(analysis_id, cape_data)
        print("✅ CAPE report saved")
        
        # Parse the report
        print("\n🔧 STEP 1: Parsing CAPE Report...")
        print("-" * 70)
        parsed_results = parser_service.parse_complete_report(
            temp_file_path, 
            structure["parsed"]
        )
        
        # Save parsed results
        parsed_files = report_structure_service.save_parsed_report(analysis_id, parsed_results)
        sections_parsed = parsed_results["metadata"]["sections_parsed"]
        print(f"✅ Parsed {len(sections_parsed)} sections: {', '.join(sections_parsed)}")
        
        # Update metadata
        report_structure_service._update_metadata(analysis_id, {
            "status": "complete",
            "analysis_type": "parse_only",
            "completed_at": datetime.now().isoformat(),
            "sections_parsed": sections_parsed
        })
        
        print(f"\n{'=' * 70}")
        print("🎉 Parse-only analysis COMPLETE!")
        print(f"{'=' * 70}")
        print(f"Analysis ID: {analysis_id}")
        print(f"Report Path: {structure['root']}")
        print(f"{'=' * 70}\n")
        
        return {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "status": "complete",
            "message": "CAPE report parsed successfully",
            "components": ["cape", "parsed"],
            "created_at": datetime.now().isoformat(),
            "report_path": str(structure["root"]),
            "sections_parsed": sections_parsed
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ Parse failed: {str(e)}")
        raise HTTPException(500, f"Parse failed: {str(e)}")
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass


@router.post("/parse-and-ai", status_code=status.HTTP_201_CREATED)
async def parse_and_ai_analysis(
    file: UploadFile = File(...),
    model_name: Optional[str] = "gemini-2.5-flash",
    enable_parallel: bool = True,
    max_parallel_sections: int = 4,
    parser_service: ParserService = Depends(get_parser_service),
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service),
):
    """
    Parse existing CAPE report AND perform AI analysis (both together)
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []
    
    try:
        if not file.filename or not file.filename.lower().endswith('.json'):
            raise HTTPException(400, "Only JSON files are supported")
        
        print(f"\n{'=' * 70}")
        print("📄🤖 Starting PARSE + AI Analysis")
        print(f"{'=' * 70}")
        print(f"File: {file.filename}")
        print(f"Analysis ID: {analysis_id}")
        print(f"AI Model: {model_name}")
        print(f"Parallel Mode: {'Enabled' if enable_parallel else 'Disabled'}")
        print(f"{'=' * 70}\n")
        
        # Create folder structure
        structure = report_structure_service.create_analysis_structure(analysis_id, file.filename)
        
        # Save uploaded CAPE report temporarily
        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = Path(temp_file.name)
            temp_files.append(temp_file_path)
        
        # Load and save CAPE data
        with open(temp_file_path, "r", encoding="utf-8") as f:
            cape_data = json.load(f)
        
        report_structure_service.save_cape_report(analysis_id, cape_data)
        print("✅ CAPE report saved")
        
        # Parse the report
        print("\n🔧 STEP 1: Parsing CAPE Report...")
        print("-" * 70)
        parsed_results = parser_service.parse_complete_report(
            temp_file_path, 
            structure["parsed"]
        )
        
        # Save parsed results
        parsed_files = report_structure_service.save_parsed_report(analysis_id, parsed_results)
        sections_parsed = parsed_results["metadata"]["sections_parsed"]
        print(f"✅ Parsed {len(sections_parsed)} sections: {', '.join(sections_parsed)}")
        
        # AI Analysis
        print("\n🤖 STEP 2: AI Analysis...")
        print("-" * 70)
        ai_analysis_result = await ai_analysis_service.analyze(
            parsed_results=parsed_results,
            model_name=model_name,
            enable_parallel=enable_parallel,
            max_parallel_sections=max_parallel_sections,
        )
        
        # Save AI analysis
        ai_files = report_structure_service.save_ai_analysis(analysis_id, ai_analysis_result)
        ai_sections = ai_analysis_result.get("sections_analyzed", [])
        print(f"✅ AI analysis of {len(ai_sections)} sections completed")
        
        # Calculate malscore
        malscore = calculate_malscore(parsed_results, ai_analysis_result)
        
        # Update metadata
        report_structure_service._update_metadata(analysis_id, {
            "status": "complete",
            "malscore": malscore,
            "analysis_type": "parse_and_ai",
            "model_used": model_name,
            "completed_at": datetime.now().isoformat(),
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_sections
        })
        
        print(f"\n{'=' * 70}")
        print("🎉 Parse + AI analysis COMPLETE!")
        print(f"{'=' * 70}")
        print(f"Analysis ID: {analysis_id}")
        print(f"Threat Score: {malscore:.1f}/10")
        print(f"Report Path: {structure['root']}")
        print(f"{'=' * 70}\n")
        
        return {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "status": "complete",
            "message": "Parse + AI analysis completed successfully",
            "components": ["cape", "parsed", "ai_analysis"],
            "malscore": malscore,
            "created_at": datetime.now().isoformat(),
            "report_path": str(structure["root"]),
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_sections
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ Parse + AI analysis failed: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(500, f"Parse + AI analysis failed: {str(e)}")
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass


@router.post("/ai-only", status_code=status.HTTP_201_CREATED)
async def ai_only_analysis(
    file: UploadFile = File(...),
    model_name: Optional[str] = "gemini-2.5-flash",
    enable_parallel: bool = True,
    max_parallel_sections: int = 4,
    parser_service: ParserService = Depends(get_parser_service),
    ai_analysis_service: AIAnalysisService = Depends(get_ai_analysis_service),
):
    """
    AI analysis on already parsed data
    """
    analysis_id = str(uuid.uuid4())
    temp_files = []
    
    try:
        if not file.filename or not file.filename.lower().endswith('.json'):
            raise HTTPException(400, "Only JSON files are supported")
        
        print(f"\n{'=' * 70}")
        print("🤖 Starting AI-ONLY Analysis")
        print(f"{'=' * 70}")
        print(f"File: {file.filename}")
        print(f"Analysis ID: {analysis_id}")
        print(f"AI Model: {model_name}")
        print(f"Parallel Mode: {'Enabled' if enable_parallel else 'Disabled'}")
        print(f"{'=' * 70}\n")
        
        # Create folder structure
        structure = report_structure_service.create_analysis_structure(analysis_id, file.filename)
        
        # Save uploaded parsed data temporarily
        with NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as temp_file:
            content = await file.read()
            temp_file.write(content)
            temp_file_path = Path(temp_file.name)
            temp_files.append(temp_file_path)
        
        # Load parsed data
        with open(temp_file_path, "r", encoding="utf-8") as f:
            parsed_data = json.load(f)
        
        # Validate it's parsed data format
        if "sections" not in parsed_data or "metadata" not in parsed_data:
            raise HTTPException(400, "File must be in parsed format (with 'sections' and 'metadata')")
        
        # Save as parsed data
        report_structure_service.save_parsed_report(analysis_id, parsed_data)
        sections_parsed = parsed_data["metadata"]["sections_parsed"]
        print(f"✅ Parsed data loaded ({len(sections_parsed)} sections)")
        
        # AI Analysis
        print("\n🤖 STEP 1: AI Analysis...")
        print("-" * 70)
        ai_analysis_result = await ai_analysis_service.analyze(
            parsed_results=parsed_data,
            model_name=model_name,
            enable_parallel=enable_parallel,
            max_parallel_sections=max_parallel_sections,
        )
        
        # Save AI analysis
        ai_files = report_structure_service.save_ai_analysis(analysis_id, ai_analysis_result)
        ai_sections = ai_analysis_result.get("sections_analyzed", [])
        print(f"✅ AI analysis of {len(ai_sections)} sections completed")
        
        # Calculate malscore
        malscore = calculate_malscore(parsed_data, ai_analysis_result)
        
        # Update metadata
        report_structure_service._update_metadata(analysis_id, {
            "status": "complete",
            "malscore": malscore,
            "analysis_type": "ai_only",
            "model_used": model_name,
            "completed_at": datetime.now().isoformat(),
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_sections
        })
        
        print(f"\n{'=' * 70}")
        print("🎉 AI-only analysis COMPLETE!")
        print(f"{'=' * 70}")
        print(f"Analysis ID: {analysis_id}")
        print(f"Threat Score: {malscore:.1f}/10")
        print(f"Report Path: {structure['root']}")
        print(f"{'=' * 70}\n")
        
        return {
            "analysis_id": analysis_id,
            "filename": file.filename,
            "status": "complete",
            "message": "AI analysis completed successfully",
            "components": ["parsed", "ai_analysis"],
            "malscore": malscore,
            "created_at": datetime.now().isoformat(),
            "report_path": str(structure["root"]),
            "sections_parsed": sections_parsed,
            "ai_sections_analyzed": ai_sections
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"\n❌ AI analysis failed: {str(e)}")
        raise HTTPException(500, f"AI analysis failed: {str(e)}")
    finally:
        for temp_file in temp_files:
            try:
                temp_file.unlink(missing_ok=True)
            except Exception:
                pass


@router.get("/reports")
async def get_all_reports():
    """
    Get all analysis reports.
    """
    try:
        analyses = report_structure_service.get_all_analyses()
        return {
            "status": "success",
            "data": analyses,
            "count": len(analyses)
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get reports: {str(e)}"
        )


@router.get("/{analysis_id}")
async def get_analysis_results(
    analysis_id: str,
    db: AsyncIOMotorDatabase = Depends(get_database_dep),
):
    """
    Retrieve complete analysis results by ID.
    """
    try:
        # Try to get from our file-based storage
        analysis = report_structure_service.get_analysis(analysis_id)
        
        if not analysis:
            # Fallback to database
            db_result = await db["analyses"].find_one({"analysis_id": analysis_id})
            
            if not db_result:
                raise HTTPException(404, f"Analysis {analysis_id} not found")
            
            db_result.pop("_id", None)
            return {"status": "success", "data": db_result}
        
        return {"status": "success", "data": analysis}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to retrieve analysis: {str(e)}")


@router.get("/{analysis_id}/components")
async def get_analysis_components(analysis_id: str):
    """
    Get available components for an analysis
    """
    analysis = report_structure_service.get_analysis(analysis_id)
    
    if not analysis:
        raise HTTPException(404, f"Analysis {analysis_id} not found")
    
    components = analysis["metadata"].get("components", {})
    
    return {
        "analysis_id": analysis_id,
        "status": "success",
        "components": components,
        "available": [k for k, v in components.items() if v]
    }


@router.get("/{analysis_id}/cape")
async def get_cape_report(analysis_id: str):
    """
    Get CAPE raw report
    """
    analysis = report_structure_service.get_analysis(analysis_id)
    
    if not analysis or "cape" not in analysis:
        raise HTTPException(404, f"CAPE report not found for {analysis_id}")
    
    return {
        "analysis_id": analysis_id,
        "type": "cape_raw",
        "data": analysis["cape"]
    }


@router.get("/{analysis_id}/parsed/{section_name}")
async def get_parsed_section(analysis_id: str, section_name: str = "all"):
    """
    Get specific parsed section or all sections
    """
    analysis = report_structure_service.get_analysis(analysis_id)
    
    if not analysis or "parsed" not in analysis:
        raise HTTPException(404, f"Parsed data not found for {analysis_id}")
    
    if section_name == "all":
        return {
            "analysis_id": analysis_id,
            "type": "parsed_all",
            "data": analysis["parsed"]
        }
    else:
        sections = analysis["parsed"].get("sections", {})
        if section_name not in sections:
            raise HTTPException(404, f"Section {section_name} not found")
        
        return {
            "analysis_id": analysis_id,
            "type": "parsed_section",
            "section": section_name,
            "data": sections[section_name]
        }


@router.get("/{analysis_id}/ai/{section_name}")
async def get_ai_section(analysis_id: str, section_name: str = "summary"):
    """
    Get specific AI analysis section or summary
    """
    analysis = report_structure_service.get_analysis(analysis_id)
    
    if not analysis or "ai_analysis" not in analysis:
        raise HTTPException(404, f"AI analysis not found for {analysis_id}")
    
    if section_name == "summary":
        return {
            "analysis_id": analysis_id,
            "type": "ai_summary",
            "data": analysis["ai_analysis"]
        }
    else:
        # For individual AI sections, load from file system
        ai_dir = report_structure_service.base_dir / analysis_id / "ai_analysis" / "sections"
        section_file = ai_dir / f"{section_name}.json"
        
        if not section_file.exists():
            raise HTTPException(404, f"AI section {section_name} not found")
        
        data = report_structure_service.load_json(section_file)
        
        return {
            "analysis_id": analysis_id,
            "type": "ai_section",
            "section": section_name,
            "data": data
        }


@router.delete("/{analysis_id}")
async def delete_analysis(analysis_id: str):
    """
    Delete an analysis.
    """
    try:
        deleted = report_structure_service.delete_analysis(analysis_id)
        
        if not deleted:
            raise HTTPException(404, f"Analysis {analysis_id} not found")
        
        return {
            "status": "success",
            "message": f"Analysis {analysis_id} deleted successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to delete analysis: {str(e)}")


@router.get("/{analysis_id}/download")
async def download_report(analysis_id: str, format: str = "json"):
    """
    Download analysis report.
    """
    try:
        analysis = report_structure_service.get_analysis(analysis_id)
        
        if not analysis:
            raise HTTPException(404, f"Analysis {analysis_id} not found")
        
        if format.lower() == "json":
            return analysis
        
        raise HTTPException(501, f"Format {format} not yet supported")
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to download report: {str(e)}")