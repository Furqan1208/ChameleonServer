# D:\FYP\ChameleonServer\app\database\create_indexes.py
"""
Script to create MongoDB indexes for optimal query performance.
Run this once during initial setup or after database changes.
"""

import asyncio

from motor.motor_asyncio import AsyncIOMotorClient

from .mongodb import DB_NAME, MONGODB_URI


async def create_indexes():
    """Create indexes for all collections"""

    client = AsyncIOMotorClient(MONGODB_URI)
    db = client[DB_NAME]

    print("Creating indexes...")

    print("- Creating indexes for 'analyses' collection...")
    await db.analyses.create_index("analysis_id", unique=True)
    await db.analyses.create_index([("created_at", -1)])
    await db.analyses.create_index("status")
    await db.analyses.create_index("analysis_type")
    await db.analyses.create_index("filename")

    print("- Creating indexes for 'cape_results' collection...")
    await db.cape_results.create_index("analysis_id", unique=True)
    await db.cape_results.create_index([("created_at", -1)])

    print("- Creating indexes for 'parsed_results' collection...")
    await db.parsed_results.create_index("analysis_id", unique=True)
    await db.parsed_results.create_index([("created_at", -1)])

    print("- Creating indexes for 'ai_results' collection...")
    await db.ai_results.create_index("analysis_id", unique=True)
    await db.ai_results.create_index([("created_at", -1)])

    print("✅ All indexes created successfully!")

    print("\nVerifying indexes:")
    for collection_name in ["analyses", "cape_results", "parsed_results", "ai_results"]:
        indexes = await db[collection_name].index_information()
        print(f"\n{collection_name}:")
        for index_name, index_info in indexes.items():
            print(f"  - {index_name}: {index_info['key']}")

    client.close()


if __name__ == "__main__":
    asyncio.run(create_indexes())
