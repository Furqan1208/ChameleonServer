# app/integrations/test_virustotal.py
"""
Quick test script for VirusTotal integration
Run with: python app/integrations/test_virustotal.py
"""

import asyncio
import sys
from pathlib import Path

import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Load environment variables from .env in project root
from dotenv import load_dotenv
load_dotenv(project_root / '.env')

# Now import and test
import asyncio
from app.integrations.virustotal_service import VirusTotalService


def print_banner():
    """Print test banner"""
    print("\n" + "="*60)
    print("🧪 VIRUSTOTAL INTEGRATION TEST - FULL RESULTS")
    print("="*60)
    print("Enter any of the following to test:")
    print("  • File Hash (SHA256, SHA1, MD5)")
    print("  • IP Address (e.g., 8.8.8.8)")
    print("  • Domain (e.g., google.com)")
    print("  • URL (e.g., http://example.com)")
    print("  • Type 'exit' to quit")
    print("="*60)


def detect_ioc_type(ioc: str) -> str:
    """Auto-detect the type of IOC"""
    ioc = ioc.strip().lower()
    
    # Check if it's a URL
    if ioc.startswith(('http://', 'https://', 'ftp://')):
        return 'url'
    
    # Check if it's an IP address
    import re
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, ioc):
        return 'ip'
    
    # Check if it's a domain (has dots but no protocol)
    if '.' in ioc and not ioc.startswith(('http', 'ftp')):
        # Simple domain check - could be improved
        return 'domain'
    
    # Check hash lengths
    if len(ioc) == 64:  # SHA256
        return 'hash'
    elif len(ioc) == 40:  # SHA1
        return 'hash'
    elif len(ioc) == 32:  # MD5
        return 'hash'
    
    # Default to hash for any hex string
    if all(c in '0123456789abcdef' for c in ioc):
        return 'hash'
    
    return 'unknown'


async def test_ioc(ioc: str, ioc_type: str, show_all: bool = True):
    """Test a single IOC - show ALL entries without truncation"""
    print(f"\n🔍 Testing {ioc_type.upper()}: {ioc}")
    print("-" * 60)
    
    try:
        async with VirusTotalService() as vt:
            start_time = asyncio.get_event_loop().time()
            
            # Analyze based on type
            if ioc_type == 'hash':
                result = await vt.analyze_hash(ioc, include_relationships=True)
            elif ioc_type == 'ip':
                result = await vt.analyze_ip(ioc, include_relationships=True)
            elif ioc_type == 'domain':
                result = await vt.analyze_domain(ioc, include_relationships=True)
            elif ioc_type == 'url':
                result = await vt.analyze_url(ioc)
            else:
                print(f"❌ Unsupported IOC type: {ioc_type}")
                return
            
            elapsed = asyncio.get_event_loop().time() - start_time
            
            # Display results
            if result.found:
                print(f"✅ Found in VirusTotal ({elapsed:.2f}s)")
                print(f"📊 Threat Level: {result.threat_level.upper()}")
                print(f"🎯 Threat Score: {result.threat_score:.1f}/100")
                print(f"🔍 Detections: {result.detection_stats.detection_ratio}")
                print(f"📈 Stats: Malicious={result.detection_stats.malicious}, "
                      f"Suspicious={result.detection_stats.suspicious}, "
                      f"Clean={result.detection_stats.harmless}")
                
                # File-specific info
                if result.file_info:
                    print(f"\n📁 File Information:")
                    print(f"   Name: {result.file_info.filename}")
                    if result.file_info.size:
                        print(f"   Size: {result.file_info.size:,} bytes")
                    print(f"   Type: {result.file_info.type_description}")
                    print(f"   First Seen: {result.file_info.first_seen}")
                    if result.file_info.tags:
                        print(f"   Tags: {', '.join(result.file_info.tags)}")
                    else:
                        print(f"   Tags: None")
                
                # Network-specific info
                if result.network_info:
                    print(f"\n🌐 Network Information:")
                    if result.network_info.country:
                        print(f"   Country: {result.network_info.country}")
                    if result.network_info.as_owner:
                        print(f"   AS Owner: {result.network_info.as_owner}")
                    if result.network_info.asn:
                        print(f"   ASN: {result.network_info.asn}")
                    if result.network_info.categories:
                        print(f"   Categories: {', '.join(result.network_info.categories)}")
                
                # Behavioral indicators
                if result.behavioral_indicators:
                    print(f"\n🔄 Behavioral Indicators:")
                    for indicator in result.behavioral_indicators:
                        print(f"   • {indicator}")
                
                # Relationships - Show ALL without truncation
                if result.relationships:
                    print(f"\n🔗 Relationships Found:")
                    for rel_type, items in result.relationships.items():
                        if items:
                            print(f"\n   {rel_type.replace('_', ' ').title()} ({len(items)} items):")
                            for i, item in enumerate(items, 1):
                                print(f"     {i:3d}. {item}")
                        else:
                            print(f"\n   {rel_type.replace('_', ' ').title()}: None")
                else:
                    print(f"\n🔗 Relationships: None found")
                
                print(f"\n🔗 View on VirusTotal: {result.vt_url}")
                
            else:
                print(f"❌ Not found in VirusTotal ({elapsed:.2f}s)")
                if result.vt_url:
                    print(f"🔗 {result.vt_url}")
            
            print("-" * 60)
            
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        import traceback
        traceback.print_exc()


async def quick_test():
    """Quick test with the WannaCry hash showing all entries"""
    print("\n" + "="*60)
    print("🚀 QUICK TEST - WannaCry Ransomware (Full Results)")
    print("="*60)
    
    # WannaCry ransomware hash
    wannacry_hash = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
    
    await test_ioc(wannacry_hash, "hash", show_all=True)


async def interactive_mode():
    """Interactive testing mode - shows all entries"""
    print_banner()
    
    while True:
        try:
            # Get user input
            user_input = input("\n🎯 Enter IOC to analyze (or 'quick'/'exit'): ").strip()
            
            if user_input.lower() == 'exit':
                print("\n👋 Exiting test...")
                break
            elif user_input.lower() == 'quick':
                await quick_test()
                continue
            elif not user_input:
                continue
            
            # Auto-detect IOC type
            ioc_type = detect_ioc_type(user_input)
            
            if ioc_type == 'unknown':
                print(f"❓ Could not detect IOC type for: {user_input}")
                print("   Please specify type manually:")
                print("   1. Hash")
                print("   2. IP Address")
                print("   3. Domain")
                print("   4. URL")
                
                type_choice = input("   Enter number (1-4): ").strip()
                type_map = {'1': 'hash', '2': 'ip', '3': 'domain', '4': 'url'}
                ioc_type = type_map.get(type_choice, 'hash')
            
            print(f"🔍 Detected as: {ioc_type.upper()}")
            print("📋 Showing ALL entries (no truncation)...")
            
            # Run analysis with full results
            await test_ioc(user_input, ioc_type, show_all=True)
            
        except KeyboardInterrupt:
            print("\n\n👋 Test interrupted by user")
            break
        except Exception as e:
            print(f"❌ Unexpected error: {e}")


def main():
    """Main function"""
    try:
        # Test if API key is available
        import os
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            print("❌ ERROR: VIRUSTOTAL_API_KEY not found in environment!")
            print("   Please add to .env file:")
            print("   VIRUSTOTAL_API_KEY=your_key_here")
            return
        
        print(f"✅ API Key loaded: {api_key[:8]}...{api_key[-4:]}")
        
        # Check command line arguments
        if len(sys.argv) > 1:
            # Test specific IOC from command line
            ioc = sys.argv[1]
            ioc_type = detect_ioc_type(ioc)
            
            if ioc_type == 'unknown' and len(sys.argv) > 2:
                ioc_type = sys.argv[2].lower()
            
            print(f"📋 Testing with FULL results (no truncation)...")
            asyncio.run(test_ioc(ioc, ioc_type, show_all=True))
        else:
            # Interactive mode
            asyncio.run(interactive_mode())
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure you're in the right directory and have installed requirements:")
        print("   pip install aiohttp")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()