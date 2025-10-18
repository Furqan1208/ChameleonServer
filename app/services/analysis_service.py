import asyncio
import os
from typing import Dict, Optional

import aiohttp
from motor.motor_asyncio import AsyncIOMotorDatabase


class AnalysisService:
    def __init__(self, database: AsyncIOMotorDatabase):
        self.database = database
        self.collection = database.malware_analysis
        self.cape_api = os.getenv("CAPE_API_URL")
        self.cape_api_key = os.getenv("CAPE_API_KEY")
        self.poll_interval = int(os.getenv("CAPE_POLL_INTERVAL", "10"))
        self.max_poll_attempts = int(os.getenv("CAPE_MAX_POLL", "30"))

    async def upload_and_analyze(self, file) -> Optional[Dict]:
        """Upload file to CAPEv2 and retrieve final JSON analysis report."""
        task_id = await self._submit_file_to_cape(file)
        if not task_id:
            return None

        report = await self._poll_for_report(task_id)
        if report:
            await self.collection.insert_one(
                {"task_id": task_id, "file_name": file.filename, "report": report}
            )
        return report

    async def _submit_file_to_cape(self, file) -> Optional[int]:
        """Submit file to CAPEv2 for analysis."""
        url = f"{self.cape_api}/tasks/create/file"
        headers = {"Authorization": f"Token {self.cape_api_key}"}

        async with aiohttp.ClientSession() as session:
            form_data = aiohttp.FormData()
            form_data.add_field("file", await file.read(), filename=file.filename)
            async with session.post(url, headers=headers, data=form_data) as resp:
                if resp.status != 200:
                    return None
                result = await resp.json()
                return result.get("task_id")

    async def _poll_for_report(self, task_id: int) -> Optional[Dict]:
        """Poll CAPEv2 server for analysis completion and get report JSON."""
        url = f"{self.cape_api}/tasks/report/{task_id}"
        headers = {"Authorization": f"Token {self.cape_api_key}"}

        for _ in range(self.max_poll_attempts):
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data:
                            return data
            await asyncio.sleep(self.poll_interval)
        return None

    # async def parse_cape_report(self, report: Dict) -> Dict:
    #     """
    #     Placeholder for future parsing logic
    #     This will extract meaningful info (TTPs, IOC, etc.)
    #     """
    #     return report
