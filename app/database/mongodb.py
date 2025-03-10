from motor import motor_asyncio
from fastapi import FastAPI
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB Configuration
MONGODB_URI = os.getenv("MONGODB_URI")
DB_NAME = os.getenv("DB_NAME", "app_database")

# Database client (global variable)
client = None

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    global client
    try:
        client = motor_asyncio.AsyncIOMotorClient(MONGODB_URI)
        await client.admin.command('ping')
        print("Connected to MongoDB Atlas")
        yield
    except Exception as e:
        print(f"Error connecting to MongoDB Atlas: {e}")
        raise
    finally:
        # Shutdown logic
        if client:
            client.close()
            print("MongoDB connection closed")

# Database access function
async def get_database():
    if client is None:
        raise RuntimeError("Database client not initialized. Make sure to use the app's lifespan.")
    return client[DB_NAME]