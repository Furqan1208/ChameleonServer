import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from motor import motor_asyncio

from app.utils.logger import get_logger

# Load environment variables
load_dotenv()

# MongoDB Configuration
MONGODB_URI = os.getenv("MONGODB_URI")
DB_NAME = os.getenv("DB_NAME", "app_database")

# Database client (global variable)
client = None

_logger = get_logger("app.database.mongodb")


# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    global client
    try:
        client = motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
        await client.admin.command("ping")
        _logger.info("Connected to MongoDB Atlas")
        
        # Create indexes on startup
        try:
            db = client[DB_NAME]
            from app.database.create_indexes import create_indexes
            await create_indexes(db)
        except Exception as e:
            _logger.warning("Failed to create/verify indexes: %s", e)
        
        yield
    except Exception as e:
        _logger.exception("Error connecting to MongoDB Atlas: %s", e)
        raise
    finally:
        # Shutdown logic
        if client:
            client.close()
            _logger.info("MongoDB connection closed")


# Database access function
async def get_database():
    if client is None:
        raise RuntimeError(
            "Database client not initialized. Make sure to use the app's lifespan."
        )
    return client[DB_NAME]
