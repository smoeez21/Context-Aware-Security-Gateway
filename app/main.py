from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import APP_NAME, APP_VERSION
from app.database.database import create_database


@asynccontextmanager
async def lifespan(app: FastAPI):

    create_database()

    yield


app = FastAPI(
    title=APP_NAME,
    description=(
        "Context-aware security gateway for controlling "
        "autonomous AI-agent access to organizational resources."
    ),
    version=APP_VERSION,
    lifespan=lifespan
)


@app.get("/")
def home():

    return {
        "system": APP_NAME,
        "status": "running",
        "version": APP_VERSION
    }


@app.get("/health")
def health_check():

    return {
        "status": "healthy",
        "service": APP_NAME,
        "database": "configured"
    }