# D:\FYP\ChameleonServer\test_enhanced_services.py
import asyncio
import json
import os
from pathlib import Path
from app.services.enhanced_model_service import EnhancedModelService
from app.services.parser_service import ParserService
from app.services.chunking_service import ChunkingService
from app.services.enhanced_analysis_service import EnhancedAnalysisService


def select_sample_report():
    """Let user select from available sample reports"""
    sample_dir = Path("app/sample_reports")
    available_reports = []
    
    print("\n📁 Available Sample Reports:")
    print("-" * 50)
    
    for i, file_path in enumerate(sample_dir.glob("*.json"), 1):
        file_size = file_path.stat().st_size
        size_mb = file_size / (1024 * 1024)
        available_reports.append(file_path)
        print(f"{i}. {file_path.name} ({size_mb:.2f} MB)")
    
    if not available_reports:
        print("❌ No JSON reports found in sample_reports directory")
        return None
    
    print(f"{len(available_reports) + 1}. Use mock data (for quick testing)")
    
    while True:
        try:
            choice = input(f"\nSelect a report (1-{len(available_reports) + 1}): ").strip()
            if not choice:
                continue
                
            choice_num = int(choice)
            
            if 1 <= choice_num <= len(available_reports):
                selected_report = available_reports[choice_num - 1]
                print(f"✅ Selected: {selected_report.name}")
                return selected_report
            elif choice_num == len(available_reports) + 1:
                print("✅ Using mock data for quick testing")
                return "mock"
            else:
                print(f"❌ Please enter a number between 1 and {len(available_reports) + 1}")
                
        except ValueError:
            print("❌ Please enter a valid number")
        except KeyboardInterrupt:
            print("\n👋 Test cancelled by user")
            return None


def get_test_options():
    """Get testing options from user"""
    print("\n🧪 Testing Options:")
    print("1. Full progressive analysis (all sections)")
    print("2. Test specific section only")
    print("3. Test chunking service only")
    print("4. Test model service only")
    print("5. Quick integration test")
    
    while True:
        try:
            choice = input("\nSelect test type (1-5): ").strip()
            if not choice:
                continue
                
            choice_num = int(choice)
            if 1 <= choice_num <= 5:
                return choice_num
            else:
                print("❌ Please enter a number between 1 and 5")
                
        except ValueError:
            print("❌ Please enter a valid number")
        except KeyboardInterrupt:
            return None


async def test_full_progressive_analysis(analysis_service, parsed_results, model_name):
    """Test full progressive analysis with all sections"""
    print("\n🚀 Starting FULL progressive analysis...")
    print("This will analyze all sections with chunking and may take several minutes.")

    confirm = input("Continue? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ Test cancelled")
        return None

    try:
        # --- REPORT-SPECIFIC OUTPUT DIRECTORY (NEW) ---
        report_name = parsed_results["metadata"]["original_report"].replace(".json", "")
        output_path = Path("temp_test_output") / "ai_analysis" / f"{report_name}_report"

        result = await analysis_service.progressive_analysis(
            parsed_results=parsed_results,
            model_name=model_name,
            output_dir=output_path
        )
        
        print(f"✅ Full analysis completed!")
        print(f"📊 Analysis ID: {result['analysis_id']}")
        print(f"📁 Output: {result['output_directory']}")
        print(f"🔢 Sections analyzed: {len(result['sections_analyzed'])}")
        print(f"🤖 Models used: {result.get('model_usage', {})}")
        
        if 'chunking_analysis' in result:
            print(f"📦 Chunking analysis: {result['chunking_analysis']}")
        
        return result
        
    except Exception as e:
        print(f"❌ Full analysis failed: {e}")
        return None


async def test_specific_section(analysis_service, parsed_results, model_name):
    """Test analysis of a specific section"""
    sections = [
        "initial_combined_analysis",
        "target_analysis", 
        "behavior_analysis",
        "memory_analysis",
        "signatures_analysis",
        "strings_analysis"
    ]
    
    print("\n📊 Available Sections:")
    for i, section in enumerate(sections, 1):
        print(f"{i}. {section}")
    
    while True:
        try:
            choice = input(f"\nSelect section (1-{len(sections)}): ").strip()
            if not choice:
                continue
                
            choice_num = int(choice)
            if 1 <= choice_num <= len(sections):
                selected_section = sections[choice_num - 1]
                break
            else:
                print(f"❌ Please enter a number between {1} and {len(sections)}")
                
        except ValueError:
            print("❌ Please enter a valid number")
        except KeyboardInterrupt:
            return None
    
    print(f"🔍 Testing section: {selected_section}")
    
    section_config = None
    for config in analysis_service.analysis_plan:
        if config["section"] == selected_section:
            section_config = config
            break
    
    if not section_config:
        print(f"❌ Section config not found for: {selected_section}")
        return None

    # --- REPORT-SPECIFIC OUTPUT DIRECTORY (NEW) ---
    report_name = parsed_results["metadata"]["original_report"].replace(".json", "")
    section_output_dir = Path("temp_test_output") / "ai_analysis" / f"{report_name}_report" / "individual_sections"
    section_output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        result = await analysis_service.analyze_section_with_fallback(
            section_config=section_config,
            parsed_results=parsed_results,
            previous_analyses={},
            model_name=model_name,
            analysis_id=f"test_section_{selected_section}",
            output_dir=section_output_dir
        )
        
        print(f"✅ Section analysis completed!")
        print(f"📝 Section: {result.get('section', 'unknown')}")
        print(f"🤖 Model: {result.get('ai_model', 'unknown')}")
        print(f"📊 Type: {result.get('analysis_type', 'unknown')}")
        
        if result.get('analysis_type') == 'chunked':
            print(f"📦 Chunks: {result.get('total_chunks', 0)} total, "
                  f"{result.get('chunks_analyzed', 0)} successful, "
                  f"{result.get('chunks_failed', 0)} failed")
        
        return result
        
    except Exception as e:
        print(f"❌ Section analysis failed: {e}")
        return None


async def test_chunking_service(chunking_service, parsed_results):
    """Test the chunking service only"""
    print("\n📦 Testing Chunking Service...")
    
    chunking_analysis = chunking_service.analyze_chunking_requirements(parsed_results)
    print("📊 Chunking Requirements Analysis:")
    for section, analysis in chunking_analysis.items():
        print(f"   {section}:")
        print(f"     - Needs chunking: {analysis.get('needs_chunking', False)}")
        print(f"     - Estimated chunks: {analysis.get('estimated_chunks', 1)}")
        if 'process_count' in analysis:
            print(f"     - Processes: {analysis['process_count']}")
        if 'total_strings' in analysis:
            print(f"     - Strings: {analysis['total_strings']}")
    
    print("\n🔍 Testing actual chunking...")
    
    if "behavior" in parsed_results["sections"]:
        behavior_chunks = chunking_service.chunk_behavior_data(parsed_results["sections"]["behavior"])
        print(f"   Behavior: {len(behavior_chunks)} chunks")
        for i, chunk in enumerate(behavior_chunks, 1):
            info = chunk["chunk_info"]
            print(f"     Chunk {i}: {info['processes_in_chunk']} processes, "
                  f"{info['estimated_tokens']} estimated tokens")
    
    if "strings" in parsed_results["sections"]:
        strings_chunks = chunking_service.chunk_strings_data(parsed_results["sections"]["strings"])
        print(f"   Strings: {len(strings_chunks)} chunks")
        for i, chunk in enumerate(strings_chunks, 1):
            info = chunk["chunk_info"]
            print(f"     Chunk {i}: {info['strings_in_chunk']} strings, "
                  f"{info['estimated_tokens']} estimated tokens")
    
    return chunking_analysis


async def test_model_service(model_service):
    """Test the model service directly"""
    print("\n🤖 Testing Model Service...")
    
    test_prompts = [
        "Please respond with 'TEST 1 SUCCESSFUL' and nothing else.",
        "What is 2 + 2? Respond with only the number.",
        "Translate 'hello' to Spanish. Respond with only the translation."
    ]
    
    models_to_test = ["gemini-2.5-flash", "grok-4.1-fast-free", "llama-3.3-70b-free"]
    
    for i, prompt in enumerate(test_prompts, 1):
        print(f"\n📝 Test {i}: {prompt[:50]}...")
        
        for model in models_to_test:
            try:
                print(f"   Trying {model}...")
                result = await model_service.process_request(prompt=prompt, model_name=model)
                response = result.get("response", "No response").strip()
                print(f"   ✅ {model}: {response[:100]}{'...' if len(response) > 100 else ''}")
                break
            except Exception as e:
                print(f"   ❌ {model}: {str(e)[:100]}...")
                continue
    
    print(f"\n🔄 Testing fallback mechanism...")
    try:
        result = await model_service.process_request_with_fallback(
            prompt="This is a fallback test. Respond with 'FALLBACK SUCCESSFUL'.",
            preferred_model="invalid-model"
        )
        print(f"✅ Fallback test successful with: {result.get('model', 'unknown')}")
    except Exception as e:
        print(f"❌ Fallback test failed: {e}")


async def quick_integration_test(analysis_service, parsed_results, model_name):
    """Quick integration test of all services"""
    print("\n⚡ Quick Integration Test...")

    # --- REPORT-SPECIFIC OUTPUT DIR (NEW) ---
    report_name = parsed_results["metadata"]["original_report"].replace(".json", "")
    output_dir = Path("temp_test_output") / "ai_analysis" / f"{report_name}_report"

    try:
        result = await analysis_service.analyze_section_with_fallback(
            section_config={
                "section": "initial_combined_analysis",
                "prompt_file": "initial_combined_analysis_prompt.txt",
                "input_sections": ["info", "statistics", "cape"],
                "requires_previous": False,
                "chunkable": False,
                "priority": 1
            },
            parsed_results=parsed_results,
            previous_analyses={},
            model_name=model_name,
            analysis_id="quick_test",
            output_dir=output_dir
        )
        
        print("✅ Quick test completed!")
        print(f"📝 Section: {result.get('section', 'unknown')}")
        print(f"🤖 Model: {result.get('ai_model', 'unknown')}")
        print(f"✅ Analysis type: {result.get('analysis_type', 'unknown')}")
        
        if 'analysis' in result:
            analysis_data = result['analysis']
            if 'executive_summary' in analysis_data:
                print(f"📊 Executive summary: {analysis_data['executive_summary'].get('overview', 'N/A')[:100]}...")
        
        return result
        
    except Exception as e:
        print(f"❌ Quick test failed: {e}")
        return None


async def test_enhanced_services():
    """Main test function for enhanced services"""
    print("🧪 Chameleon AI Enhanced Services Test Suite")
    print("=" * 60)
    
    try:
        report_path = select_sample_report()
        if report_path is None:
            return False
        
        test_type = get_test_options()
        if test_type is None:
            return False
        
        print("\n1. Initializing services...")
        model_service = EnhancedModelService()
        parser_service = ParserService(models_dir=Path("app/parser"))
        chunking_service = ChunkingService()
        analysis_service = EnhancedAnalysisService(model_service, parser_service, chunking_service)
        
        print("✅ Services initialized successfully")
        
        parsed_results = None
        if report_path == "mock":
            print("📝 Using mock data for testing...")
            parsed_results = {
                "metadata": {
                    "original_report": "mock_report.json",
                    "parsed_timestamp": "2024-01-01T00:00:00",
                    "sections_parsed": ["info", "target", "behavior"]
                },
                "sections": {
                    "info": {"id": 123, "category": "file", "package": "exe"},
                    "target": {"file_name": "test.exe", "file_size": 1024},
                    "behavior": {"processes": [{"process_id": 1234, "process_name": "test.exe"}]}
                }
            }
        else:
            print(f"2. Parsing report: {report_path.name}")
            parsed_output_dir = Path("temp_test_output") / "parsed"
            parsed_results = parser_service.parse_complete_report(
                report_path, 
                parsed_output_dir
            )
            print(f"✅ Report parsed. Sections: {len(parsed_results['metadata']['sections_parsed'])}")
        
        model_name = "gemini-2.5-flash"
        
        if test_type == 1:
            await test_full_progressive_analysis(analysis_service, parsed_results, model_name)
        elif test_type == 2:
            await test_specific_section(analysis_service, parsed_results, model_name)
        elif test_type == 3:
            await test_chunking_service(chunking_service, parsed_results)
        elif test_type == 4:
            await test_model_service(model_service)
        elif test_type == 5:
            await quick_integration_test(analysis_service, parsed_results, model_name)
        
        print("\n🎉 Test completed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    Path("temp_test_output").mkdir(exist_ok=True)
    
    success = asyncio.run(test_enhanced_services())
    
    if success:
        print("\n✅ All tests completed successfully!")
        print("💡 Next: Run the main server and test the API endpoints")
    else:
        print("\n❌ Some tests failed. Check the errors above.")
    
    print(f"\n📁 Test outputs saved to: temp_test_output/")
