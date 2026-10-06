from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.database.database import get_db
from app.database.models import (
    Agent,
    Policy,
    Resource,
)
from app.schemas.policy import (
    PolicyCreate,
    PolicyResponse,
)


router = APIRouter(
    prefix="/policies",
    tags=["Policies"]
)


@router.get(
    "",
    response_model=list[PolicyResponse]
)
def get_policies(
    db: Session = Depends(get_db)
):
    return db.query(Policy).all()


@router.get(
    "/{policy_id}",
    response_model=PolicyResponse
)
def get_policy(
    policy_id: int,
    db: Session = Depends(get_db)
):

    policy = (
        db.query(Policy)
        .filter(Policy.id == policy_id)
        .first()
    )

    if not policy:
        raise HTTPException(
            status_code=404,
            detail="Policy not found"
        )

    return policy


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=201
)
def create_policy(
    payload: PolicyCreate,
    db: Session = Depends(get_db)
):

    agent = (
        db.query(Agent)
        .filter(Agent.id == payload.agent_id)
        .first()
    )

    if not agent:
        raise HTTPException(
            status_code=404,
            detail="Agent not found"
        )

    resource = (
        db.query(Resource)
        .filter(
            Resource.id == payload.resource_id
        )
        .first()
    )

    if not resource:
        raise HTTPException(
            status_code=404,
            detail="Resource not found"
        )

    action = payload.action.value
    destination = payload.destination.value
    effect = payload.effect.value

    policy = Policy(
        agent_id=payload.agent_id,
        resource_id=payload.resource_id,
        action=action,
        destination=destination,
        effect=effect,
        description=payload.description
    )

    try:
        db.add(policy)
        db.commit()
        db.refresh(policy)

    except IntegrityError:

        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="This policy already exists"
        )

    return policy