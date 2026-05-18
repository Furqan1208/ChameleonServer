# D:\FYP\ChameleonServer\app\database\create_indexes.py
"""
Script to create MongoDB indexes for optimal query performance.
Run this once during initial setup or after database changes.
"""

import asyncio

from motor.motor_asyncio import AsyncIOMotorClient

from .mongodb import DB_NAME, MONGODB_URI
from app.utils.logger import get_logger

_logger = get_logger("app.database.create_indexes")


async def create_indexes(db=None):
    """
    Create indexes for all collections.
    If db is None, creates a new connection. Otherwise uses the provided database.
    """
    
    if db is None:
        # Standalone usage - create connection
        client = AsyncIOMotorClient(MONGODB_URI)
        db = client[DB_NAME]
        close_after = True
    else:
        # Called from lifespan - use existing connection
        close_after = False

    _logger.info("Creating/verifying indexes...")

    try:
        _logger.info("- Creating indexes for 'analyses' collection...")
        await db.analyses.create_index("analysis_id", unique=True)
        await db.analyses.create_index([("created_at", -1)])
        await db.analyses.create_index("status")
        await db.analyses.create_index("analysis_type")
        await db.analyses.create_index("filename")

        _logger.info("- Creating indexes for 'cape_results' collection...")
        await db.cape_results.create_index("analysis_id", unique=True)
        await db.cape_results.create_index([("created_at", -1)])

        _logger.info("- Creating indexes for 'parsed_results' collection...")
        await db.parsed_results.create_index("analysis_id", unique=True)
        await db.parsed_results.create_index([("created_at", -1)])

        _logger.info("- Creating indexes for 'ai_results' collection...")
        await db.ai_results.create_index("analysis_id", unique=True)
        await db.ai_results.create_index([("created_at", -1)])

        _logger.info("✅ All indexes created successfully!")

        _logger.info("Verifying indexes:")
        for collection_name in ["analyses", "cape_results", "parsed_results", "ai_results"]:
            indexes = await db[collection_name].index_information()
            _logger.info("%s indexes: %s", collection_name, list(indexes.keys()))
    finally:
        if close_after and db is not None:
            client.close()


if __name__ == "__main__":
    asyncio.run(create_indexes())
