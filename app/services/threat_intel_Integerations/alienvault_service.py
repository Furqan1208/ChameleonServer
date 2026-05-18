import os
from datetime import datetime
from typing import Optional

import httpx
from app.utils.logger import get_logger

_logger = get_logger("app.services.alienvault")


class AlienVaultOTXService:
    """Server-side AlienVault OTX integration."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self):
        self.api_key = os.getenv("ALIENVAULT_OTX_API_KEY", "")
        if not self.api_key:
            _logger.warning("ALIENVAULT_OTX_API_KEY not set")

    @property
    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": self.api_key, "Accept": "application/json"}

    async def _get(self, client: httpx.AsyncClient, path: str) -> Optional[dict]:
        try:
            response = await client.get(
                f"{self.BASE_URL}{path}",
                headers=self._headers,
                timeout=30,
            )
            if response.status_code == 404:
                return None
            if response.status_code == 403:
                raise RuntimeError("Invalid AlienVault OTX API key.")
            if response.status_code == 429:
                raise RuntimeError("AlienVault OTX rate limit exceeded.")
            if not response.is_success:
                return None
            return response.json()
        except (RuntimeError, httpx.TimeoutException):
            raise
        except Exception as e:
            _logger.exception("[OTX] Request error %s: %s", path, e)
            return None

    @staticmethod
    def _as_list(value) -> list:
        if not value:
                        return []
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        if isinstance(value, set):
            return list(value)
        return [value]

    # -------------------------------------------------------------------------
    # Public entry point
    # -------------------------------------------------------------------------

    async def scan_indicator(self, indicator: str, ioc_type: str) -> dict:
        """
        Scan an IP, domain, hostname, URL, or file hash against AlienVault OTX.
        ioc_type: ip | domain | url | hash
        """
        async with httpx.AsyncClient() as client:
            match ioc_type:
                case "ip":
                    return await self._scan_ip(client, indicator)
                case "domain":
                    return await self._scan_domain(client, indicator)
                case "url":
                    return await self._scan_url(client, indicator)
                case "hash":
                    return await self._scan_hash(client, indicator)
                case _:
                    raise ValueError(f"Unsupported OTX indicator type: {ioc_type}")

    # -------------------------------------------------------------------------
    # Indicator scanners — fetch general + geo sections in parallel
    # -------------------------------------------------------------------------

    async def _scan_ip(self, client: httpx.AsyncClient, ip: str) -> dict:
        import asyncio

        general, geo, reputation, url_list, passive_dns = await asyncio.gather(
            self._get(client, f"/indicators/IPv4/{ip}/general"),
            self._get(client, f"/indicators/IPv4/{ip}/geo"),
            self._get(client, f"/indicators/IPv4/{ip}/reputation"),
            self._get(client, f"/indicators/IPv4/{ip}/url_list"),
            self._get(client, f"/indicators/IPv4/{ip}/passive_dns"),
            return_exceptions=True,
        )
        return self._build_result(
            indicator=ip,
            ioc_type="ip",
            general=general if isinstance(general, dict) else None,
            extra={
                "geo": geo if isinstance(geo, dict) else None,
                "reputation": reputation if isinstance(reputation, dict) else None,
                "url_list": (url_list or {}).get("url_list", [])
                if isinstance(url_list, dict)
                else [],
                "passive_dns": (passive_dns or {}).get("passive_dns", [])
                if isinstance(passive_dns, dict)
                else [],
            },
        )

    async def _scan_domain(self, client: httpx.AsyncClient, domain: str) -> dict:
        import asyncio

        general, geo, url_list, passive_dns = await asyncio.gather(
            self._get(client, f"/indicators/domain/{domain}/general"),
            self._get(client, f"/indicators/domain/{domain}/geo"),
            self._get(client, f"/indicators/domain/{domain}/url_list"),
            self._get(client, f"/indicators/domain/{domain}/passive_dns"),
            return_exceptions=True,
        )
        return self._build_result(
            indicator=domain,
            ioc_type="domain",
            general=general if isinstance(general, dict) else None,
            extra={
                "geo": geo if isinstance(geo, dict) else None,
                "url_list": (url_list or {}).get("url_list", [])
                if isinstance(url_list, dict)
                else [],
                "passive_dns": (passive_dns or {}).get("passive_dns", [])
                if isinstance(passive_dns, dict)
                else [],
            },
        )

    async def _scan_url(self, client: httpx.AsyncClient, url: str) -> dict:
        import urllib.parse

        encoded = urllib.parse.quote(url, safe="")
        general = await self._get(client, f"/indicators/url/{encoded}/general")
        return self._build_result(
            indicator=url,
            ioc_type="url",
            general=general if isinstance(general, dict) else None,
        )

    async def _scan_hash(self, client: httpx.AsyncClient, hash_: str) -> dict:
        import asyncio

        # Detect hash type by length
        {32: "md5", 40: "sha1", 64: "sha256"}.get(len(hash_), "sha256")
        general, analysis = await asyncio.gather(
            self._get(client, f"/indicators/file/{hash_}/general"),
            self._get(client, f"/indicators/file/{hash_}/analysis"),
            return_exceptions=True,
        )
        return self._build_result(
            indicator=hash_,
            ioc_type="hash",
            general=general if isinstance(general, dict) else None,
            extra={"analysis": analysis if isinstance(analysis, dict) else None},
        )

    # -------------------------------------------------------------------------
    # Result builder
    # -------------------------------------------------------------------------

    def _build_result(
        self,
        indicator: str,
        ioc_type: str,
        general: Optional[dict],
        extra: dict = {},
    ) -> dict:
        if not general:
            return {
                "ioc": indicator,
                "ioc_type": ioc_type,
                "found": False,
                "pulse_count": 0,
                "threat_level": "unknown",
                "tags": [],
                "malware_families": [],
                "adversaries": [],
                "references": [],
                "timestamp": datetime.utcnow().isoformat(),
            }

        pulse_info = general.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        pulse_count = pulse_info.get("count", len(pulses))

        # Aggregate tags, malware families, adversaries from pulses
        tags: set = set()
        malware_families: set = set()
        adversaries: set = set()
        references: list = []

        for pulse in pulses[:20]:  # cap to avoid huge payloads
            tags.update(self._as_list(pulse.get("tags")))
            for mf in self._as_list(pulse.get("malware_families")):
                malware_families.add(mf.get("display_name", mf.get("id", "")))
            for adv in self._as_list(pulse.get("adversary")):
                if isinstance(adv, dict):
                    adversary_name = adv.get("name") or adv.get("display_name") or adv.get("id")
                    if adversary_name:
                        adversaries.add(adversary_name)
                elif isinstance(adv, str):
                    cleaned = adv.strip()
                    if cleaned:
                        adversaries.add(cleaned)
            references.extend(self._as_list(pulse.get("references"))[:3])

        threat_level = "unknown"
        if pulse_count > 10:
            threat_level = "high"
        elif pulse_count > 3:
            threat_level = "medium"
        elif pulse_count > 0:
            threat_level = "low"
        else:
            threat_level = "clean"

        return {
            "ioc": indicator,
            "ioc_type": ioc_type,
            "found": pulse_count > 0,
            "pulse_count": pulse_count,
            "threat_level": threat_level,
            "tags": list(tags)[:20],
            "malware_families": list(malware_families)[:10],
            "adversaries": list(adversaries)[:10],
            "references": list(set(references))[:10],
            "country": general.get("country_name")
            or (extra.get("geo") or {}).get("country_name"),
            "asn": general.get("asn"),
            "whois": general.get("whois"),
            "reputation": general.get("reputation", 0),
            **{k: v for k, v in extra.items() if k not in ("geo",)},
            "timestamp": datetime.utcnow().isoformat(),
        }
