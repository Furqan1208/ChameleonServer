# D:\FYP\ChameleonServer\run_progressive_with_model.py
import requests
import json
import time
import sys
from pathlib import Path

def get_available_models():
    """Get list of available models from the server"""
    return [
        "gemini-2.5-flash",
        "gemini-2.5-pro", 
        "llama-3.2-3b",
        "MiniMaxAI",
        "gpt-oss-20b"
    ]

def test_model_quickly(model_name):
    """Quick test to see if a model is working"""
    BASE_URL = "http://localhost:8001"
    
    print(f"🔍 Testing {model_name}...", end=" ")
    
    try:
        response = requests.post(
            f"{BASE_URL}/analysis/ai-only?prompt=Say+OK&model_name={model_name}",
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            response_text = result.get('response', '').strip()
            if response_text:
                print("✅ WORKING")
                return True
            else:
                print("❌ NO RESPONSE")
                return False
        else:
            print(f"❌ FAILED ({response.status_code})")
            return False
            
    except Exception as e:
        print(f"❌ ERROR ({str(e)[:20]}...)")
        return False

def run_progressive_analysis_with_model(model_name, report_path):
    """Run progressive analysis with the selected model"""
    
    BASE_URL = "http://localhost:8001"
    
    print(f"\n🚀 Starting Progressive Analysis")
    print("=" * 50)
    print(f"📄 Report: {report_path.name}")
    print(f"🤖 Model: {model_name}")
    print(f"📊 Size: {report_path.stat().st_size / (1024 * 1024):.1f} MB")
    print()
    
    try:
        with open(report_path, 'rb') as f:
            files = {'file': (report_path.name, f, 'application/json')}
            
            start_time = time.time()
            response = requests.post(
                f"{BASE_URL}/analysis/parse-and-analyze?model_name={model_name}",
                files=files,
                timeout=600  # 10 minute timeout
            )
            elapsed_time = time.time() - start_time
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Analysis completed in {elapsed_time:.1f}s!")
            
            # Display results
            print(f"\n📊 ANALYSIS RESULTS")
            print("=" * 40)
            print(f"📋 Analysis ID: {result.get('analysis_id')}")
            print(f"🔧 Parsed Sections: {len(result.get('parsed_sections', []))}")
            print(f"🤖 AI Analyses: {len(result.get('ai_analyses_performed', []))}")
            print(f"📁 Output Directory: {result.get('output_directory')}")
            
            # Show analysis progress
            print(f"\n🗺️ ANALYSIS PROGRESS:")
            analyses = result.get('ai_analyses_performed', [])
            for i, analysis in enumerate(analyses, 1):
                print(f"   {i}. {analysis}")
            
            # Check output files
            output_dir = Path(result.get('output_directory', ''))
            if output_dir.exists():
                print(f"\n📁 GENERATED FILES:")
                successful_analyses = 0
                total_analyses = 0
                
                for file in output_dir.glob("*_ai_analysis.json"):
                    total_analyses += 1
                    try:
                        with open(file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        
                        size_kb = file.stat().st_size / 1024
                        status = "✅" if 'error' not in data else "❌"
                        
                        if 'error' not in data:
                            successful_analyses += 1
                        
                        print(f"   {status} {file.name} ({size_kb:.1f} KB)")
                        
                    except Exception as e:
                        print(f"   ❌ {file.name} (read error)")
                
                print(f"\n📈 SUCCESS RATE: {successful_analyses}/{total_analyses} analyses")
                
                # Show final report preview
                final_file = output_dir / "final_synthesis_ai_analysis.json"
                if final_file.exists():
                    print(f"\n🎯 FINAL REPORT PREVIEW:")
                    try:
                        with open(final_file, 'r', encoding='utf-8') as f:
                            final_data = json.load(f)
                        
                        if 'analysis' in final_data:
                            analysis = final_data['analysis']
                            if 'comprehensive_report' in analysis:
                                report = analysis['comprehensive_report']
                                print(f"   📝 Title: {report.get('report_title', 'N/A')}")
                                print(f"   🆔 Sample: {report.get('sample_identifier', 'N/A')}")
                            
                            if 'threat_overview' in analysis:
                                threat = analysis['threat_overview']
                                print(f"   🦠 Family: {threat.get('malware_family', 'N/A')}")
                                print(f"   ⚠️  Level: {threat.get('sophistication_level', 'N/A')}")
                    
                    except Exception as e:
                        print(f"   ⚠️  Could not read final report: {e}")
            
            return {
                'success': True,
                'time': elapsed_time,
                'analysis_id': result.get('analysis_id'),
                'output_dir': result.get('output_directory'),
                'sections_analyzed': len(analyses)
            }
            
        else:
            print(f"❌ Analysis failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return {'success': False, 'error': response.text}
            
    except requests.exceptions.Timeout:
        print("❌ Analysis timed out. The report might be too large.")
        return {'success': False, 'error': 'Timeout'}
    except Exception as e:
        print(f"❌ Analysis error: {e}")
        return {'success': False, 'error': str(e)}

def main():
    """Main function to run progressive analysis with model selection"""
    
    BASE_URL = "http://localhost:8001"
    REPORTS_DIR = Path("D:/FYP/Chameleonserverv1/app/cape_parser/sample_reports")
    
    print("🚀 ChameleonServer - Model Selection")
    print("Run progressive analysis with your chosen model")
    print("=" * 60)
    
    # Check server
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running on http://localhost:8001")
        else:
            print("❌ Server not responding")
            sys.exit(1)
    except:
        print("❌ Cannot connect to server")
        sys.exit(1)
    
    # Get available reports
    reports = list(REPORTS_DIR.glob("*.json"))
    if not reports:
        print("❌ No CAPE reports found")
        sys.exit(1)
    
    # Step 1: Select a report
    print(f"\n📁 STEP 1: Select a CAPE Report")
    print("=" * 30)
    for i, report in enumerate(reports, 1):
        size_mb = report.stat().st_size / (1024 * 1024)
        print(f"   {i}. {report.name} ({size_mb:.1f} MB)")
    
    try:
        report_choice = int(input(f"\n🎯 Choose report (1-{len(reports)}): "))
        if report_choice < 1 or report_choice > len(reports):
            print("❌ Invalid choice")
            return
        
        selected_report = reports[report_choice - 1]
        print(f"✅ Selected: {selected_report.name}")
        
    except ValueError:
        print("❌ Please enter a valid number")
        return
    
    # Step 2: Select a model
    print(f"\n🤖 STEP 2: Select AI Model")
    print("=" * 30)
    available_models = get_available_models()
    
    # Test each model first
    working_models = []
    for i, model in enumerate(available_models, 1):
        if test_model_quickly(model):
            working_models.append(model)
            print(f"   {i}. {model} ✅")
        else:
            print(f"   {i}. {model} ❌ (not available)")
    
    if not working_models:
        print("❌ No working models found!")
        return
    
    try:
        model_choice = int(input(f"\n🎯 Choose model (1-{len(working_models)}): "))
        if model_choice < 1 or model_choice > len(working_models):
            print("❌ Invalid choice")
            return
        
        selected_model = working_models[model_choice - 1]
        print(f"✅ Selected: {selected_model}")
        
    except ValueError:
        print("❌ Please enter a valid number")
        return
    
    # Step 3: Run analysis
    print(f"\n⚡ STEP 3: Running Analysis")
    print("=" * 30)
    
    result = run_progressive_analysis_with_model(selected_model, selected_report)
    
    if result['success']:
        print(f"\n🎉 ANALYSIS COMPLETED SUCCESSFULLY!")
        print(f"💡 Output directory: {result['output_dir']}")
        print(f"⏱️  Total time: {result['time']:.1f}s")
        print(f"📊 Sections analyzed: {result['sections_analyzed']}/8")
    else:
        print(f"\n💥 ANALYSIS FAILED!")
        print(f"❌ Error: {result.get('error', 'Unknown error')}")
    
    print(f"\n📖 API Documentation: http://localhost:8001/docs")

if __name__ == "__main__":
    main()