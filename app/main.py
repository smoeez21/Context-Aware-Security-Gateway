from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import APP_NAME, APP_VERSION
from app.database.database import create_database

from app.api.agents import router as agents_router
from app.api.resources import router as resources_router
from app.api.policies import router as policies_router


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


app.include_router(agents_router)
app.include_router(resources_router)
app.include_router(policies_router)


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