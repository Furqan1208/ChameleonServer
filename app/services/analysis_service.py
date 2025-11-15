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
        self.cape_api_token = os.getenv("CAPE_API_TOKEN")
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
        url = f"{self.cape_api}tasks/create/file/"
        headers = {"Authorization": f"Token {self.cape_api_token}"}

        data = await file.read()

        async with aiohttp.ClientSession() as session:
            form_data = aiohttp.FormData()
            form_data.add_field("file", data, filename=file.filename)

            async with session.post(url, headers=headers, data=form_data) as resp:
                text = await resp.text()
                print("Status:", resp.status, "Response:", text)

                if resp.status != 200:
                    return None

                result = await resp.json()
                task_ids = result.get("data", {}).get("task_ids", [])
                return task_ids[0] if task_ids else None

    async def _poll_for_report(self, task_id: int) -> Optional[Dict]:
        """Poll CAPEv2 server for analysis completion and get final report."""
        url = f"{self.cape_api}tasks/get/report/{task_id}/"
        headers = {"Authorization": f"Token {self.cape_api_token}"}

        for attempt in range(self.max_poll_attempts):
            print(f"Polling CAPE report for task {task_id}... attempt {attempt + 1}")

            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as resp:
                    text = await resp.text()

                    if resp.status != 200:
                        print("Non-200 from CAPE:", resp.status, text)
                        await asyncio.sleep(self.poll_interval)
                        continue

                    try:
                        data = await resp.json()
                    except Exception:
                        print("CAPE returned non-JSON:", text)
                        await asyncio.sleep(self.poll_interval)
                        continue

                    # CAPE still processing
                    if data.get("error") is True:
                        error_value = data.get("error_value", "")
                        print("CAPE not ready:", error_value)

                        if "Reports directory does not exist" in error_value:
                            # task running, report not created yet
                            await asyncio.sleep(self.poll_interval)
                            continue

                        # other errors (rare)
                        print("CAPE error:", error_value)
                        await asyncio.sleep(self.poll_interval)
                        continue

                    # Report ready!
                    return data

            await asyncio.sleep(self.poll_interval)

        print("Max poll attempts reached.")
        return None

    # async def parse_cape_report(self, report: Dict) -> Dict:
    #     """
    #     Placeholder for future parsing logic
    #     This will extract meaningful info (TTPs, IOC, etc.)
    #     """
    #     return report
