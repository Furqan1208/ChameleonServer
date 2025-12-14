# app/integrations/virustotal_service.py
"""
Comprehensive VirusTotal Integration Service
Supports: Hashes, IPs, Domains, URLs, Filenames
Features: Caching, Threat Scoring, Behavioral Analysis, Async Support
"""

import os
import json
import base64
import asyncio
import time
import math
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path

import aiohttp
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorDatabase

# Cache implementation
@dataclass
class CacheEntry:
    timestamp: float
    data: Dict[str, Any]


class VirusTotalCache:
    """Simple in-memory cache for VirusTotal results"""
    
    def __init__(self, ttl_seconds: int = 300):  # 5 minutes default
        self.cache: Dict[str, CacheEntry] = {}
        self.ttl = ttl_seconds
    
    def get(self, key: str) -> Optional[Dict[str, Any]]:
        entry = self.cache.get(key)
        if not entry:
            return None
        
        if time.time() - entry.timestamp > self.ttl:
            del self.cache[key]
            return None
        
        return entry.data
    
    def set(self, key: str, data: Dict[str, Any]):
        self.cache[key] = CacheEntry(timestamp=time.time(), data=data)
    
    def clear(self):
        self.cache.clear()


# Models
class VTFileInfo(BaseModel):
    """VirusTotal file information"""
    hash: str
    filename: Optional[str] = None
    size: Optional[int] = None
    type_description: Optional[str] = None
    first_seen: Optional[str] = None
    last_analysis: Optional[str] = None
    reputation: Optional[int] = None
    tags: List[str] = Field(default_factory=list)


class VTDetectionStats(BaseModel):
    """Detection statistics"""
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    timeout: int = 0
    total: int = 0
    
    @property
    def detection_ratio(self) -> str:
        """Format as malicious/total"""
        total_detected = self.malicious + self.suspicious
        return f"{total_detected}/{self.total}" if self.total > 0 else "0/0"
    
    @property
    def threat_score(self) -> float:
        """Calculate threat score (0-100)"""
        if self.total == 0:
            return 0.0
        # Weight malicious more heavily
        score = (self.malicious * 1.0 + self.suspicious * 0.5) / self.total * 100
        return min(score, 100.0)


class VTNetworkInfo(BaseModel):
    """Network information for IPs/Domains"""
    asn: Optional[int] = None
    as_owner: Optional[str] = None
    country: Optional[str] = None
    network: Optional[str] = None
    registrar: Optional[str] = None  # For domains
    categories: List[str] = Field(default_factory=list)


class VTAnalysisResult(BaseModel):
    """Standardized analysis result"""
    ioc: str
    ioc_type: str  # hash, ip, domain, url, filename
    found: bool = False
    detection_stats: VTDetectionStats = Field(default_factory=VTDetectionStats)
    threat_level: str = "unknown"  # high, medium, low, clean, unknown
    threat_score: float = 0.0
    file_info: Optional[VTFileInfo] = None
    network_info: Optional[VTNetworkInfo] = None
    behavioral_indicators: List[str] = Field(default_factory=list)
    relationships: Dict[str, List[str]] = Field(default_factory=dict)  # e.g., {"contacted_ips": ["1.1.1.1"]}
    sandbox_data: Optional[Dict[str, Any]] = None
    raw_data: Optional[Dict[str, Any]] = None
    vt_url: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class VirusTotalService:
    """Comprehensive VirusTotal API integration service"""
    
    def __init__(self, api_key: Optional[str] = None, cache_ttl: int = 300):
        self.api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        if not self.api_key:
            raise ValueError("VIRUSTOTAL_API_KEY not found in environment")
        
        self.base_url = "https://www.virustotal.com/api/v3"
        self.cache = VirusTotalCache(ttl_seconds=cache_ttl)
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers={
                'x-apikey': self.api_key,
                'Accept': 'application/json'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make async request to VirusTotal API"""
        if not self.session:
            self.session = aiohttp.ClientSession(
                headers={'x-apikey': self.api_key, 'Accept': 'application/json'}
            )
        
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            async with self.session.get(url, params=params, timeout=30) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 404:
                    return {"error": "Not found"}
                elif response.status == 429:
                    return {"error": "Rate limit exceeded"}
                else:
                    return {"error": f"API error {response.status}"}
        except asyncio.TimeoutError:
            return {"error": "Request timeout"}
        except Exception as e:
            return {"error": str(e)}
    
    async def analyze_hash(self, hash_value: str, include_relationships: bool = True) -> VTAnalysisResult:
        """Analyze file hash (MD5, SHA1, SHA256)"""
        cache_key = f"hash_{hash_value}"
        cached = self.cache.get(cache_key)
        if cached and not include_relationships:
            return VTAnalysisResult(**cached)
        
        # Get file information
        file_data = await self._make_request(f"/files/{hash_value}")
        
        if "error" in file_data:
            return VTAnalysisResult(
                ioc=hash_value,
                ioc_type="hash",
                found=False,
                vt_url=f"https://www.virustotal.com/gui/file/{hash_value}"
            )
        
        # Parse the response
        result = self._parse_file_response(file_data, hash_value)
        
        if include_relationships:
            # Get relationships (async parallel calls)
            relationship_tasks = [
                self._get_contacted_ips(hash_value),
                self._get_contacted_domains(hash_value),
                self._get_dropped_files(hash_value),
                self._get_execution_parents(hash_value),
                self._get_behaviors(hash_value)
            ]
            
            relationship_results = await asyncio.gather(*relationship_tasks)
            
            # Update relationships
            result.relationships.update({
                "contacted_ips": relationship_results[0],
                "contacted_domains": relationship_results[1],
                "dropped_files": relationship_results[2],
                "execution_parents": relationship_results[3]
            })
            
            # Update behavioral indicators
            if relationship_results[4]:
                result.behavioral_indicators = self._extract_behavioral_indicators(relationship_results[4])
                result.sandbox_data = relationship_results[4]
        
        # Cache the result
        self.cache.set(cache_key, result.dict())
        
        return result
    
    async def analyze_ip(self, ip_address: str, include_relationships: bool = True) -> VTAnalysisResult:
        """Analyze IP address"""
        cache_key = f"ip_{ip_address}"
        cached = self.cache.get(cache_key)
        if cached and not include_relationships:
            return VTAnalysisResult(**cached)
        
        # Get IP information
        ip_data = await self._make_request(f"/ip_addresses/{ip_address}")
        
        if "error" in ip_data:
            return VTAnalysisResult(
                ioc=ip_address,
                ioc_type="ip",
                found=False,
                vt_url=f"https://www.virustotal.com/gui/ip-address/{ip_address}"
            )
        
        # Parse the response
        result = self._parse_ip_response(ip_data, ip_address)
        
        if include_relationships:
            # Get relationships
            relationship_tasks = [
                self._get_ip_resolutions(ip_address),
                self._get_communicating_files(ip_address),
                self._get_downloaded_files(ip_address),
                self._get_hosted_urls(ip_address)
            ]
            
            relationship_results = await asyncio.gather(*relationship_tasks)
            
            result.relationships.update({
                "resolved_domains": relationship_results[0],
                "communicating_files": relationship_results[1],
                "downloaded_files": relationship_results[2],
                "hosted_urls": relationship_results[3]
            })
        
        # Cache the result
        self.cache.set(cache_key, result.dict())
        
        return result
    
    async def analyze_domain(self, domain: str, include_relationships: bool = True) -> VTAnalysisResult:
        """Analyze domain"""
        cache_key = f"domain_{domain}"
        cached = self.cache.get(cache_key)
        if cached and not include_relationships:
            return VTAnalysisResult(**cached)
        
        # Get domain information
        domain_data = await self._make_request(f"/domains/{domain}")
        
        if "error" in domain_data:
            return VTAnalysisResult(
                ioc=domain,
                ioc_type="domain",
                found=False,
                vt_url=f"https://www.virustotal.com/gui/domain/{domain}"
            )
        
        # Parse the response
        result = self._parse_domain_response(domain_data, domain)
        
        if include_relationships:
            # Get relationships
            relationship_tasks = [
                self._get_domain_resolutions(domain),
                self._get_subdomains(domain),
                self._get_domain_communicating_files(domain),
                self._get_domain_referring_files(domain)
            ]
            
            relationship_results = await asyncio.gather(*relationship_tasks)
            
            result.relationships.update({
                "resolved_ips": relationship_results[0],
                "subdomains": relationship_results[1],
                "communicating_files": relationship_results[2],
                "referring_files": relationship_results[3]
            })
        
        # Cache the result
        self.cache.set(cache_key, result.dict())
        
        return result
    
    async def analyze_url(self, url: str) -> VTAnalysisResult:
        """Analyze URL"""
        cache_key = f"url_{url}"
        cached = self.cache.get(cache_key)
        if cached:
            return VTAnalysisResult(**cached)
        
        # Encode URL for VT API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        # Get URL information
        url_data = await self._make_request(f"/urls/{url_id}")
        
        if "error" in url_data:
            return VTAnalysisResult(
                ioc=url,
                ioc_type="url",
                found=False,
                vt_url=f"https://www.virustotal.com/gui/url/{url_id}"
            )
        
        # Parse the response
        result = self._parse_url_response(url_data, url)
        
        # Cache the result
        self.cache.set(cache_key, result.dict())
        
        return result
    
    async def analyze_filename(self, filename: str, limit: int = 5) -> List[VTAnalysisResult]:
        """Search for files by filename"""
        cache_key = f"filename_{filename}_{limit}"
        cached = self.cache.get(cache_key)
        if cached:
            return [VTAnalysisResult(**item) for item in cached]
        
        # Search for files
        search_data = await self._make_request(
            f"/search?query=name:\"{filename}\"",
            params={"limit": limit}
        )
        
        if "error" in search_data or "data" not in search_data:
            return []
        
        results = []
        for file_item in search_data["data"]:
            file_hash = file_item.get("id")
            if file_hash:
                # Get full analysis for each file
                file_result = await self.analyze_hash(file_hash, include_relationships=False)
                results.append(file_result)
        
        # Cache the results
        self.cache.set(cache_key, [r.dict() for r in results])
        
        return results
    
    # Helper methods for relationships
    async def _get_contacted_ips(self, hash_value: str, limit: int = 20) -> List[str]:
        """Get IPs contacted by file"""
        data = await self._make_request(
            f"/files/{hash_value}/contacted_ips",
            params={"limit": limit}
        )
        return self._extract_ids(data)
    
    async def _get_contacted_domains(self, hash_value: str, limit: int = 20) -> List[str]:
        """Get domains contacted by file"""
        data = await self._make_request(
            f"/files/{hash_value}/contacted_domains",
            params={"limit": limit}
        )
        return self._extract_ids(data)
    
    async def _get_dropped_files(self, hash_value: str, limit: int = 10) -> List[str]:
        """Get files dropped by file"""
        data = await self._make_request(
            f"/files/{hash_value}/dropped_files",
            params={"limit": limit}
        )
        return self._extract_ids(data)
    
    async def _get_execution_parents(self, hash_value: str, limit: int = 10) -> List[str]:
        """Get parent files"""
        data = await self._make_request(
            f"/files/{hash_value}/execution_parents",
            params={"limit": limit}
        )
        return self._extract_ids(data)
    
    async def _get_behaviors(self, hash_value: str, limit: int = 2) -> Optional[Dict]:
        """Get behavioral data"""
        data = await self._make_request(
            f"/files/{hash_value}/behaviours",
            params={"limit": limit}
        )
        return data if "error" not in data else None
    
    async def _get_ip_resolutions(self, ip_address: str, limit: int = 25) -> List[str]:
        """Get domains resolving to IP"""
        data = await self._make_request(
            f"/ip_addresses/{ip_address}/resolutions",
            params={"limit": limit}
        )
        return self._extract_hostnames(data)
    
    async def _get_communicating_files(self, ip_address: str, limit: int = 15) -> List[str]:
        """Get files communicating with IP"""
        data = await self._make_request(
            f"/ip_addresses/{ip_address}/communicating_files",
            params={"limit": limit}
        )
        return self._extract_ids(data)
    
    async def _get_downloaded_files(self, ip_address: str, limit: int = 15) -> List[str]:
        """Get files downloaded from IP"""
        data = await self._make_request(
            f"/ip_addresses/{ip_address}/downloaded_files",
            params={"limit": limit}
        )
        return self._extract_ids(data)
    
    async def _get_hosted_urls(self, ip_address: str, limit: int = 15) -> List[str]:
        """Get URLs hosted on IP"""
        data = await self._make_request(
            f"/ip_addresses/{ip_address}/urls",
            params={"limit": limit}
        )
        return self._extract_ids(data)
    
    async def _get_domain_resolutions(self, domain: str, limit: int = 25) -> List[str]:
        """Get IPs domain resolves to"""
        data = await self._make_request(
            f"/domains/{domain}/resolutions",
            params={"limit": limit}
        )
        return self._extract_ips(data)
    
    async def _get_subdomains(self, domain: str, limit: int = 20) -> List[str]:
        """Get subdomains"""
        data = await self._make_request(
            f"/domains/{domain}/subdomains",
            params={"limit": limit}
        )
        return self._extract_ids(data)
    
    async def _get_domain_communicating_files(self, domain: str, limit: int = 15) -> List[str]:
        """Get files communicating with domain"""
        data = await self._make_request(
            f"/domains/{domain}/communicating_files",
            params={"limit": limit}
        )
        return self._extract_ids(data)
    
    async def _get_domain_referring_files(self, domain: str, limit: int = 15) -> List[str]:
        """Get files referencing domain"""
        data = await self._make_request(
            f"/domains/{domain}/referrer_files",
            params={"limit": limit}
        )
        return self._extract_ids(data)
    
    # Parsing methods
    def _parse_file_response(self, data: Dict, hash_value: str) -> VTAnalysisResult:
        """Parse file/hash response"""
        attrs = data.get("data", {}).get("attributes", {})
        stats_data = attrs.get("last_analysis_stats", {})
        
        detection_stats = VTDetectionStats(
            malicious=stats_data.get("malicious", 0),
            suspicious=stats_data.get("suspicious", 0),
            harmless=stats_data.get("harmless", 0),
            undetected=stats_data.get("undetected", 0),
            timeout=stats_data.get("timeout", 0),
            total=sum(stats_data.values())
        )
        
        # Determine threat level
        threat_level = self._determine_threat_level(detection_stats)
        
        # File information
        file_info = VTFileInfo(
            hash=hash_value,
            filename=attrs.get("meaningful_name") or attrs.get("names", [""])[0] if attrs.get("names") else None,
            size=attrs.get("size"),
            type_description=attrs.get("type_description"),
            first_seen=self._timestamp_to_str(attrs.get("first_submission_date")),
            last_analysis=self._timestamp_to_str(attrs.get("last_analysis_date")),
            reputation=attrs.get("reputation", 0),
            tags=attrs.get("tags", [])
        )
        
        return VTAnalysisResult(
            ioc=hash_value,
            ioc_type="hash",
            found=True,
            detection_stats=detection_stats,
            threat_level=threat_level,
            threat_score=detection_stats.threat_score,
            file_info=file_info,
            vt_url=f"https://www.virustotal.com/gui/file/{hash_value}",
            raw_data=data
        )
    
    def _parse_ip_response(self, data: Dict, ip_address: str) -> VTAnalysisResult:
        """Parse IP response"""
        attrs = data.get("data", {}).get("attributes", {})
        stats_data = attrs.get("last_analysis_stats", {})
        
        detection_stats = VTDetectionStats(
            malicious=stats_data.get("malicious", 0),
            suspicious=stats_data.get("suspicious", 0),
            harmless=stats_data.get("harmless", 0),
            undetected=stats_data.get("undetected", 0),
            timeout=stats_data.get("timeout", 0),
            total=sum(stats_data.values())
        )
        
        threat_level = self._determine_threat_level(detection_stats)
        
        # Network information
        network_info = VTNetworkInfo(
            asn=attrs.get("asn"),
            as_owner=attrs.get("as_owner"),
            country=attrs.get("country"),
            network=attrs.get("network"),
            categories=list(attrs.get("categories", {}).values())
        )
        
        return VTAnalysisResult(
            ioc=ip_address,
            ioc_type="ip",
            found=True,
            detection_stats=detection_stats,
            threat_level=threat_level,
            threat_score=detection_stats.threat_score,
            network_info=network_info,
            vt_url=f"https://www.virustotal.com/gui/ip-address/{ip_address}",
            raw_data=data
        )
    
    def _parse_domain_response(self, data: Dict, domain: str) -> VTAnalysisResult:
        """Parse domain response"""
        attrs = data.get("data", {}).get("attributes", {})
        stats_data = attrs.get("last_analysis_stats", {})
        
        detection_stats = VTDetectionStats(
            malicious=stats_data.get("malicious", 0),
            suspicious=stats_data.get("suspicious", 0),
            harmless=stats_data.get("harmless", 0),
            undetected=stats_data.get("undetected", 0),
            timeout=stats_data.get("timeout", 0),
            total=sum(stats_data.values())
        )
        
        threat_level = self._determine_threat_level(detection_stats)
        
        # Network information
        network_info = VTNetworkInfo(
            registrar=attrs.get("registrar"),
            categories=list(attrs.get("categories", {}).values())
        )
        
        return VTAnalysisResult(
            ioc=domain,
            ioc_type="domain",
            found=True,
            detection_stats=detection_stats,
            threat_level=threat_level,
            threat_score=detection_stats.threat_score,
            network_info=network_info,
            vt_url=f"https://www.virustotal.com/gui/domain/{domain}",
            raw_data=data
        )
    
    def _parse_url_response(self, data: Dict, url: str) -> VTAnalysisResult:
        """Parse URL response"""
        attrs = data.get("data", {}).get("attributes", {})
        stats_data = attrs.get("last_analysis_stats", {})
        
        detection_stats = VTDetectionStats(
            malicious=stats_data.get("malicious", 0),
            suspicious=stats_data.get("suspicious", 0),
            harmless=stats_data.get("harmless", 0),
            undetected=stats_data.get("undetected", 0),
            timeout=stats_data.get("timeout", 0),
            total=sum(stats_data.values())
        )
        
        threat_level = self._determine_threat_level(detection_stats)
        
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        return VTAnalysisResult(
            ioc=url,
            ioc_type="url",
            found=True,
            detection_stats=detection_stats,
            threat_level=threat_level,
            threat_score=detection_stats.threat_score,
            vt_url=f"https://www.virustotal.com/gui/url/{url_id}",
            raw_data=data
        )
    
    # Utility methods
    def _determine_threat_level(self, stats: VTDetectionStats) -> str:
        """Determine threat level based on detection stats"""
        if stats.total == 0:
            return "unknown"
        
        malicious_ratio = stats.malicious / stats.total
        
        if malicious_ratio >= 0.1 or stats.malicious >= 5:
            return "high"
        elif malicious_ratio >= 0.05 or stats.malicious >= 2:
            return "medium"
        elif stats.suspicious > 0 or stats.malicious > 0:
            return "low"
        else:
            return "clean"
    
    def _extract_behavioral_indicators(self, behavior_data: Dict) -> List[str]:
        """Extract behavioral indicators from sandbox data"""
        indicators = []
        
        if "data" not in behavior_data:
            return indicators
        
        for behavior in behavior_data["data"]:
            attrs = behavior.get("attributes", {})
            summary = attrs.get("summary", {})
            
            # Extract key behavioral indicators
            if summary.get("files_written"):
                indicators.append(f"Files written: {len(summary['files_written'])}")
            if summary.get("files_dropped"):
                indicators.append(f"Files dropped: {len(summary['files_dropped'])}")
            if summary.get("registry_keys_set"):
                indicators.append(f"Registry modifications: {len(summary['registry_keys_set'])}")
            if summary.get("processes_created"):
                indicators.append(f"Processes created: {len(summary['processes_created'])}")
            if summary.get("dns_lookups"):
                indicators.append(f"DNS lookups: {len(summary['dns_lookups'])}")
            if summary.get("http_conversations"):
                indicators.append(f"HTTP requests: {len(summary['http_conversations'])}")
            
            # MITRE ATT&CK techniques
            if "mitre_attack_techniques" in summary:
                for technique in summary["mitre_attack_techniques"][:5]:
                    indicators.append(f"MITRE: {technique}")
        
        return indicators[:10]  # Limit to top 10 indicators
    
    def _extract_ids(self, data: Dict) -> List[str]:
        """Extract IDs from relationship data"""
        if "error" in data or "data" not in data:
            return []
        return [item.get("id", "") for item in data["data"] if item.get("id")]
    
    def _extract_hostnames(self, data: Dict) -> List[str]:
        """Extract hostnames from resolution data"""
        if "error" in data or "data" not in data:
            return []
        
        hostnames = []
        for item in data["data"]:
            attrs = item.get("attributes", {})
            hostname = attrs.get("host_name")
            if hostname:
                hostnames.append(hostname)
        return hostnames
    
    def _extract_ips(self, data: Dict) -> List[str]:
        """Extract IPs from resolution data"""
        if "error" in data or "data" not in data:
            return []
        
        ips = []
        for item in data["data"]:
            attrs = item.get("attributes", {})
            ip = attrs.get("ip_address")
            if ip:
                ips.append(ip)
        return ips
    
    def _timestamp_to_str(self, timestamp: Optional[int]) -> Optional[str]:
        """Convert Unix timestamp to ISO format string"""
        if timestamp:
            return datetime.fromtimestamp(timestamp).isoformat()
        return None


# FastAPI integration helpers
async def get_virustotal_service() -> VirusTotalService:
    """Dependency injection for FastAPI"""
    return VirusTotalService()


# Test function
async def test_virustotal():
    """Test the VirusTotal service"""
    async with VirusTotalService() as vt:
        # Test hash analysis
        print("Testing hash analysis...")
        result = await vt.analyze_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        print(f"Hash analysis: {result.found}")
        print(f"Threat level: {result.threat_level}")
        print(f"Score: {result.threat_score}")
        
        # Test IP analysis
        print("\nTesting IP analysis...")
        result = await vt.analyze_ip("8.8.8.8")
        print(f"IP analysis: {result.found}")
        print(f"Threat level: {result.threat_level}")
        
        # Test domain analysis
        print("\nTesting domain analysis...")
        result = await vt.analyze_domain("google.com")
        print(f"Domain analysis: {result.found}")
        print(f"Threat level: {result.threat_level}")


if __name__ == "__main__":
    # Run test if executed directly
    asyncio.run(test_virustotal())