# app/services/threat_intel_Integerations/urlhaus_service.py
import os
from datetime import datetime

import httpx
from app.utils.logger import get_logger

_logger = get_logger("app.services.urlhaus")


class URLhausService:
    """
    Server-side URLhaus integration.
    URLhaus is part of the abuse.ch ecosystem along with ThreatFox.
    """

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self):
        # URLhaus uses the same API key as ThreatFox (optional for most endpoints)
        self.api_key = os.getenv("THREATFOX_API_KEY", "")
        if not self.api_key:
            _logger.warning("THREATFOX_API_KEY not set — using anonymous URLhaus access")

    @property
    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["Auth-Key"] = self.api_key
        return headers

    def _detect_indicator_type(self, indicator: str) -> str:
        """Detect the type of indicator"""
        indicator_lower = indicator.lower().strip()
        
        # Check if it's a URL
        if indicator_lower.startswith(('http://', 'https://')):
            return 'url'
        
        # Check if it's a hash (SHA256 or MD5)
        if len(indicator_lower) == 64 and all(c in '0123456789abcdef' for c in indicator_lower):
            return 'hash'
        if len(indicator_lower) == 32 and all(c in '0123456789abcdef' for c in indicator_lower):
            return 'hash'
        
        # Check if it's likely a tag (alphanumeric with underscores/dashes)
        if indicator_lower.replace('_', '').replace('-', '').replace('.', '').isalnum() and len(indicator_lower) > 3:
            # Could be a tag or a host
            # If it contains a dot, likely a host
            if '.' in indicator_lower:
                return 'host'
            return 'tag'
        
        # Default to host
        return 'host'

    async def check_indicator(self, indicator: str) -> dict:
        """Check an indicator (auto-detect type)"""
        indicator_type = self._detect_indicator_type(indicator)
        
        if indicator_type == 'url':
            return await self.check_url(indicator)
        elif indicator_type == 'hash':
            return await self.check_hash(indicator)
        elif indicator_type == 'host':
            return await self.check_host(indicator)
        elif indicator_type == 'tag':
            return await self.check_tag(indicator)
        else:
            return await self.check_url(indicator)

    async def check_url(self, url: str) -> dict:
        """Check a URL in URLhaus"""
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.post(
                    f"{self.BASE_URL}/url/",
                    headers=self._headers,
                    data={"url": url}
                )
                if resp.status_code == 429:
                    raise RuntimeError("URLhaus rate limit exceeded.")
                if not resp.is_success:
                    return self._not_found(url, "url", f"API error: {resp.status_code}")
                
                data = resp.json()
                return self._parse_url_response(data, url)
            except RuntimeError:
                raise
            except httpx.TimeoutException:
                raise RuntimeError("URLhaus request timed out.")
            except Exception as e:
                _logger.exception("[URLhaus] check_url error: %s", e)
                return self._not_found(url, "url", str(e))

    async def check_hash(self, hash_value: str) -> dict:
        """Check a hash (payload) in URLhaus"""
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.post(
                    f"{self.BASE_URL}/payload/",
                    headers=self._headers,
                    data={"hash": hash_value}
                )
                if resp.status_code == 429:
                    raise RuntimeError("URLhaus rate limit exceeded.")
                if not resp.is_success:
                    return self._not_found(hash_value, "hash", f"API error: {resp.status_code}")
                
                data = resp.json()
                return self._parse_payload_response(data, hash_value)
            except RuntimeError:
                raise
            except httpx.TimeoutException:
                raise RuntimeError("URLhaus request timed out.")
            except Exception as e:
                _logger.exception("[URLhaus] check_hash error: %s", e)
                return self._not_found(hash_value, "hash", str(e))

    async def check_host(self, host: str) -> dict:
        """Check a host in URLhaus"""
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.post(
                    f"{self.BASE_URL}/host/",
                    headers=self._headers,
                    data={"host": host}
                )
                if resp.status_code == 429:
                    raise RuntimeError("URLhaus rate limit exceeded.")
                if not resp.is_success:
                    return self._not_found(host, "host", f"API error: {resp.status_code}")
                
                data = resp.json()
                return self._parse_host_response(data, host)
            except RuntimeError:
                raise
            except httpx.TimeoutException:
                raise RuntimeError("URLhaus request timed out.")
            except Exception as e:
                _logger.exception("[URLhaus] check_host error: %s", e)
                return self._not_found(host, "host", str(e))

    async def check_tag(self, tag: str) -> dict:
        """Check a tag in URLhaus"""
        async with httpx.AsyncClient(timeout=20) as client:
            try:
                resp = await client.post(
                    f"{self.BASE_URL}/tag/",
                    headers=self._headers,
                    data={"tag": tag}
                )
                if resp.status_code == 429:
                    raise RuntimeError("URLhaus rate limit exceeded.")
                if not resp.is_success:
                    return self._not_found(tag, "tag", f"API error: {resp.status_code}")
                
                data = resp.json()
                return self._parse_tag_response(data, tag)
            except RuntimeError:
                raise
            except httpx.TimeoutException:
                raise RuntimeError("URLhaus request timed out.")
            except Exception as e:
                _logger.exception("[URLhaus] check_tag error: %s", e)
                return self._not_found(tag, "tag", str(e))

    # -------------------------------------------------------------------------
    # Response Parsers
    # -------------------------------------------------------------------------

    def _parse_url_response(self, data: dict, url: str) -> dict:
        """Parse URLhaus URL lookup response"""
        query_status = data.get("query_status", "")
        
        if query_status != "ok":
            return self._not_found(url, "url", query_status)
        
        threat = data.get("threat", "")
        threat_level = self._get_threat_level(threat)
        
        return {
            "ioc": url,
            "ioc_type": "url",
            "url": data.get("url") or url,
            "found": True,
            "threat_level": threat_level,
            "query_status": query_status,
            "id": data.get("id"),
            "url_id": data.get("id"),
            "urlhaus_reference": data.get("urlhaus_reference"),
            "url_status": data.get("url_status"),
            "host": data.get("host"),
            "date_added": data.get("date_added"),
            "last_online": data.get("last_online"),
            "threat": threat,
            "reporter": data.get("reporter"),
            "larted": data.get("larted"),
            "tags": data.get("tags", []),
            "payloads": data.get("payloads", []),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _parse_payload_response(self, data: dict, hash_value: str) -> dict:
        """Parse URLhaus payload (hash) lookup response"""
        query_status = data.get("query_status", "")
        
        if query_status != "ok":
            return self._not_found(hash_value, "hash", query_status)
        
        signature = data.get("signature")
        threat_level = self._get_threat_level(signature)
        
        return {
            "ioc": hash_value,
            "ioc_type": "hash",
            "found": True,
            "threat_level": threat_level,
            "query_status": query_status,
            "md5_hash": data.get("md5_hash"),
            "sha256_hash": data.get("sha256_hash"),
            "file_type": data.get("file_type"),
            "file_size": data.get("file_size"),
            "signature": signature,
            "firstseen": data.get("firstseen"),
            "lastseen": data.get("lastseen"),
            "url_count": data.get("url_count"),
            "urlhaus_download": data.get("urlhaus_download"),
            "virustotal": data.get("virustotal"),
            "urls": data.get("urls", []),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _parse_host_response(self, data: dict, host: str) -> dict:
        """Parse URLhaus host lookup response"""
        query_status = data.get("query_status", "")
        
        if query_status != "ok":
            return self._not_found(host, "host", query_status)
        
        url_count = data.get("url_count", 0)
        threat_level = "high" if url_count > 10 else "medium" if url_count > 0 else "low"
        
        return {
            "ioc": host,
            "ioc_type": "host",
            "found": True,
            "threat_level": threat_level,
            "query_status": query_status,
            "urlhaus_reference": data.get("urlhaus_reference"),
            "host": data.get("host"),
            "firstseen": data.get("firstseen"),
            "url_count": url_count,
            "blacklists": data.get("blacklists", {}),
            "urls": data.get("urls", []),
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _parse_tag_response(self, data: dict, tag: str) -> dict:
        """Parse URLhaus tag lookup response"""
        query_status = data.get("query_status", "")
        
        if query_status != "ok":
            return self._not_found(tag, "tag", query_status)
        
        urls = data.get("urls", [])
        threat_level = "high" if len(urls) > 10 else "medium" if len(urls) > 0 else "low"
        
        return {
            "ioc": tag,
            "ioc_type": "tag",
            "found": True,
            "threat_level": threat_level,
            "query_status": query_status,
            "tag": data.get("tag"),
            "url_count": len(urls),
            "urls": urls[:20],  # Limit to first 20
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _get_threat_level(self, threat: str) -> str:
        """Determine threat level from threat type"""
        if not threat:
            return "low"
        
        threat_lower = threat.lower()
        
        if "malware_download" in threat_lower or "botnet" in threat_lower:
            return "high"
        if "phishing" in threat_lower or "spam" in threat_lower:
            return "medium"
        return "low"

    def _not_found(self, indicator: str, ioc_type: str, reason: str = "Not found") -> dict:
        """Return a not-found result"""
        return {
            "ioc": indicator,
            "ioc_type": ioc_type,
            "found": False,
            "threat_level": "unknown",
            "query_status": "no_results",
            "error": reason,
            "timestamp": datetime.utcnow().isoformat(),
        }
