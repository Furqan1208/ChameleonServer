import asyncio
import json
from pathlib import Path

from app.services.ai_analysis_service import AIAnalysisService
from app.services.chunking_service import ChunkingService
from app.services.model_service import ModelService
from app.services.parser_service import ParserService


def select_sample_report():
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
            choice = input(
                f"\nSelect a report (1-{len(available_reports) + 1}): "
            ).strip()
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
                print(
                    f"❌ Please enter a number between 1 and {len(available_reports) + 1}"
                )

        except ValueError:
            print("❌ Please enter a valid number")
        except KeyboardInterrupt:
            print("\n👋 Test cancelled by user")
            return None


def get_test_options():
    print("\n🧪 Testing Options:")
    print("1. Full AI analysis (all sections)")
    print("2. Test chunking service only")
    print("3. Test model service only")
    print("4. Quick integration test")

    while True:
        try:
            choice = input("\nSelect test type (1-4): ").strip()
            if not choice:
                continue

            choice_num = int(choice)
            if 1 <= choice_num <= 4:
                return choice_num
            else:
                print("❌ Please enter a number between 1 and 4")

        except ValueError:
            print("❌ Please enter a valid number")
        except KeyboardInterrupt:
            return None


async def test_full_analysis(analysis_service, parsed_results, model_name):
    print("\n🚀 Starting full AI analysis...")
    print("This will analyze all sections and may take several minutes.")

    confirm = input("Continue? (y/N): ").strip().lower()
    if confirm != "y":
        print("❌ Test cancelled")
        return None

    try:
        result = await analysis_service.analyze(
            parsed_results=parsed_results, model_name=model_name
        )

        print("\n✅ Full analysis completed!")
        print(f"📊 Analysis ID: {result['analysis_id']}")
        print(f"🔢 Sections analyzed: {len(result['sections_analyzed'])}")
        print(f"🤖 Models used: {result.get('model_usage', {})}")

        if "chunking_summary" in result:
            print(f"📦 Chunking summary: {result['chunking_summary']}")

        save_results(result, "full_analysis")

        return result

    except Exception as e:
        print(f"❌ Full analysis failed: {e}")
        import traceback

        traceback.print_exc()
        return None


async def test_chunking_service(chunking_service, parsed_results):
    print("\n📦 Testing Chunking Service...")

    chunking_analysis = chunking_service.analyze_chunking_requirements(parsed_results)

    print("\n📊 Chunking Requirements Analysis:")
    for section, analysis in chunking_analysis.items():
        print(f"   {section}:")
        print(f"     - Needs chunking: {analysis.get('needs_chunking', False)}")
        print(f"     - Estimated chunks: {analysis.get('estimated_chunks', 1)}")
        if "process_count" in analysis:
            print(f"     - Processes: {analysis['process_count']}")
        if "total_strings" in analysis:
            print(f"     - Strings: {analysis['total_strings']}")

    print("\n🔍 Testing actual chunking...")

    if "behavior" in parsed_results["sections"]:
        behavior_chunks = chunking_service.chunk_behavior_data(
            parsed_results["sections"]["behavior"]
        )
        print(f"   Behavior: {len(behavior_chunks)} chunks")
        for i, chunk in enumerate(behavior_chunks, 1):
            info = chunk["chunk_info"]
            print(
                f"     Chunk {i}: {info['processes_in_chunk']} processes, "
                f"{info['estimated_tokens']} estimated tokens"
            )

    if "strings" in parsed_results["sections"]:
        strings_chunks = chunking_service.chunk_strings_data(
            parsed_results["sections"]["strings"]
        )
        print(f"   Strings: {len(strings_chunks)} chunks")
        for i, chunk in enumerate(strings_chunks, 1):
            info = chunk["chunk_info"]
            print(
                f"     Chunk {i}: {info['strings_in_chunk']} strings, "
                f"{info['estimated_tokens']} estimated tokens"
            )

    return chunking_analysis


async def test_model_service(model_service):
    print("\n🤖 Testing Model Service...")

    test_prompts = [
        "Please respond with 'TEST 1 SUCCESSFUL' and nothing else.",
        "What is 2 + 2? Respond with only the number.",
        "Translate 'hello' to Spanish. Respond with only the translation.",
    ]

    available_models = model_service.get_available_models()
    print(f"Available models: {len(available_models)}")

    models_to_test = (
        available_models[:3] if len(available_models) >= 3 else available_models
    )

    for i, prompt in enumerate(test_prompts, 1):
        print(f"\n📝 Test {i}: {prompt[:50]}...")

        for model in models_to_test:
            try:
                print(f"   Trying {model}...")
                result = await model_service.process_request(
                    prompt=prompt, model_name=model
                )
                response = result.get("response", "No response").strip()
                print(
                    f"   ✅ {model}: {response[:100]}{'...' if len(response) > 100 else ''}"
                )

                if "api_key_index" in result:
                    print(f"      Used API key: {result['api_key_index']}")

                break
            except Exception as e:
                print(f"   ❌ {model}: {str(e)[:100]}...")
                continue

    print("\n🔄 Testing Gemini multi-key fallback...")
    try:
        result = await model_service.process_request(
            prompt="This is a multi-key fallback test. Respond with 'FALLBACK SUCCESSFUL'.",
            model_name="gemini-2.5-flash",
        )
        print(f"✅ Fallback test successful")
        print(f"   Model: {result.get('model', 'unknown')}")
        print(f"   API Key used: {result.get('api_key_index', 'N/A')}")
    except Exception as e:
        print(f"❌ Fallback test failed: {e}")


async def quick_integration_test(analysis_service, parsed_results, model_name):
    print("\n⚡ Quick Integration Test...")

    try:
        section_analyzer = analysis_service.section_analyzer

        result = await section_analyzer.analyze_section(
            section_config={
                "section": "initial_combined_analysis",
                "prompt_file": "initial_combined_analysis_prompt.txt",
                "input_sections": ["info", "statistics", "cape"],
                "requires_previous": False,
                "chunkable": False,
                "priority": 1,
            },
            parsed_results=parsed_results,
            previous_analyses={},
            model_name=model_name,
            analysis_id="quick_test",
        )

        print("✅ Quick test completed!")
        print(f"📝 Section: {result.get('section', 'unknown')}")
        print(f"🤖 Model: {result.get('ai_model', 'unknown')}")
        print(f"✅ Analysis type: {result.get('type', 'unknown')}")

        if "analysis" in result:
            analysis_data = result["analysis"]
            if isinstance(analysis_data, dict):
                if "executive_summary" in analysis_data:
                    summary = analysis_data["executive_summary"]
                    if isinstance(summary, dict) and "overview" in summary:
                        print(f"📊 Executive summary: {summary['overview'][:100]}...")

        save_results(result, "quick_test")

        return result

    except Exception as e:
        print(f"❌ Quick test failed: {e}")
        import traceback

        traceback.print_exc()
        return None


def save_results(result, test_name):
    output_dir = Path("temp_test_output") / "results"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / f"{test_name}_result.json"

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False, default=str)
        print(f"💾 Results saved to: {output_file}")
    except Exception as e:
        print(f"⚠️  Could not save results: {e}")


async def test_services():
    print("🧪 Chameleon AI Services Test Suite")
    print("=" * 60)

    try:
        report_path = select_sample_report()
        if report_path is None:
            return False

        test_type = get_test_options()
        if test_type is None:
            return False

        print("\n1. Initializing services...")
        model_service = ModelService()
        parser_service = ParserService(models_dir=Path("app/parser"))
        chunking_service = ChunkingService()
        analysis_service = AIAnalysisService(
            model_service, parser_service, chunking_service
        )

        print("✅ Services initialized successfully")

        parsed_results = None
        if report_path == "mock":
            print("📝 Using mock data for testing...")
            parsed_results = {
                "metadata": {
                    "original_report": "mock_report.json",
                    "parsed_timestamp": "2024-01-01T00:00:00",
                    "sections_parsed": ["info", "target", "behavior"],
                },
                "sections": {
                    "info": {"id": 123, "category": "file", "package": "exe"},
                    "target": {"file_name": "test.exe", "file_size": 1024},
                    "behavior": {
                        "processes": [
                            {
                                "process_id": 1234,
                                "process_name": "test.exe",
                                "calls": [],
                            }
                        ]
                    },
                    "statistics": {"total_api_calls": 0},
                    "cape": {"payloads": []},
                },
            }
        else:
            print(f"2. Parsing report: {report_path.name}")
            parsed_results = parser_service.parse_complete_report(
                report_path, Path("./temp_test_output") / "parsed_reports"
            )
            print(
                f"✅ Report parsed. Sections: {len(parsed_results['metadata']['sections_parsed'])}"
            )

        model_name = "gemini-2.5-flash"

        if test_type == 1:
            await test_full_analysis(analysis_service, parsed_results, model_name)
        elif test_type == 2:
            await test_chunking_service(chunking_service, parsed_results)
        elif test_type == 3:
            await test_model_service(model_service)
        elif test_type == 4:
            await quick_integration_test(analysis_service, parsed_results, model_name)

        print("\n🎉 Test completed!")
        return True

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    output_dir = Path("temp_test_output")
    output_dir.mkdir(exist_ok=True)
    (output_dir / "results").mkdir(exist_ok=True)

    success = asyncio.run(test_services())

    if success:
        print("\n✅ All tests completed successfully!")
        print("💡 Next: Run the main server and test the API endpoints")
    else:
        print("\n❌ Some tests failed. Check the errors above.")

    print("\n📁 Test outputs saved to: temp_test_output/results/")
