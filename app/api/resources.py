from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import Resource
from app.schemas.resource import (
    ResourceCreate,
    ResourceResponse,
)


router = APIRouter(
    prefix="/resources",
    tags=["Resources"]
)


@router.get(
    "",
    response_model=list[ResourceResponse]
)
def get_resources(
    db: Session = Depends(get_db)
):
    return db.query(Resource).all()


@router.get(
    "/{resource_id}",
    response_model=ResourceResponse
)
def get_resource(
    resource_id: int,
    db: Session = Depends(get_db)
):

    resource = (
        db.query(Resource)
        .filter(Resource.id == resource_id)
        .first()
    )

    if not resource:
        raise HTTPException(
            status_code=404,
            detail="Resource not found"
        )

    return resource


@router.post(
    "",
    response_model=ResourceResponse,
    status_code=201
)
def create_resource(
    payload: ResourceCreate,
    db: Session = Depends(get_db)
):

    existing = (
        db.query(Resource)
        .filter(
            Resource.resource_code
            == payload.resource_code
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Resource code already exists"
        )

    sensitivity = payload.sensitivity.value

    resource = Resource(
        resource_code=payload.resource_code,
        name=payload.name,
        resource_type=payload.resource_type.upper(),
        sensitivity=sensitivity,
        description=payload.description
    )

    db.add(resource)
    db.commit()
    db.refresh(resource)

    return resource