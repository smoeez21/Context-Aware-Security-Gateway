from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Agent
from app.schemas.agent import (
    AgentCreate,
    AgentResponse,
)
from app.security.credentials import hash_credential


router = APIRouter(
    prefix="/agents",
    tags=["Agents"]
)


@router.get(
    "",
    response_model=list[AgentResponse]
)
def get_agents(
    db: Session = Depends(get_db)
):
    return db.query(Agent).all()


@router.get(
    "/{agent_id}",
    response_model=AgentResponse
)
def get_agent(
    agent_id: int,
    db: Session = Depends(get_db)
):

    agent = (
        db.query(Agent)
        .filter(Agent.id == agent_id)
        .first()
    )

    if not agent:
        raise HTTPException(
            status_code=404,
            detail="Agent not found"
        )

    return agent


@router.post(
    "",
    response_model=AgentResponse,
    status_code=201
)
def create_agent(
    payload: AgentCreate,
    db: Session = Depends(get_db)
):

    existing = (
        db.query(Agent)
        .filter(
            Agent.agent_code
            == payload.agent_code
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Agent code already exists"
        )

    agent = Agent(
        agent_code=payload.agent_code,
        name=payload.name,
        department=payload.department,
        role=payload.role,
        status=payload.status,
        credential_hash=hash_credential(
            payload.credential
        )
    )

    db.add(agent)
    db.commit()
    db.refresh(agent)

    return agent