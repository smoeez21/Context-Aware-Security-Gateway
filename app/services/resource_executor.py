
import json

from sqlalchemy.orm import Session

from app.database.execution_models import (
    ResourceState,
    ResourceExecution,
)


# Dummy data used only for demonstration.
DEMO_CONTENT = {
    "Sales Data": {
        "monthly_sales": 125000,
        "region": "North",
    },
    "Customer Data": {
        "customer_count": 150,
        "customer_type": "Synthetic",
    },
    "Employee Data": {
        "employee_count": 45,
    },
    "Employee Salary": {
        "sample_salary": 50000,
    },
    "Research Notes": {
        "project": "AI Security Research",
    },
    "Financial Records": {
        "annual_budget": 250000,
    },
    "Credentials": {
        "demo_token": "FAKE-NONFUNCTIONAL-TOKEN",
    },
}


def execute_resource(
    db: Session,
    access_request,
    resource,
    payload_data=None,
):
    """
    Execute a permitted operation against a
    simulated organizational resource.

    Caller must enforce authorization/risk decisions.
    This function must never be exposed as a public API.

    Changes remain in the caller's database transaction.
    """

    # --------------------------------------------------------
    # Prevent duplicate execution
    # --------------------------------------------------------

    existing = (
        db.query(ResourceExecution)
        .filter(
            ResourceExecution.request_id
            == access_request.id
        )
        .first()
    )

    if existing:
        return json.loads(
            existing.result_json
        )

    # --------------------------------------------------------
    # Get or initialize dummy resource state
    # --------------------------------------------------------

    state = (
        db.query(ResourceState)
        .filter(
            ResourceState.resource_id == resource.id
        )
        .first()
    )

    if state is None:
        state = ResourceState(
            resource_id=resource.id,
            content_json=json.dumps(
                DEMO_CONTENT.get(
                    resource.name,
                    {},
                )
            ),
        )

        db.add(state)
        db.flush()

    current_data = json.loads(
        state.content_json
    )

    action = access_request.action

    destination = access_request.destination

    # --------------------------------------------------------
    # READ
    # --------------------------------------------------------

    if action == "READ":

        result = {
            "status": "EXECUTED",
            "action": "READ",
            "data": current_data,
        }

    # --------------------------------------------------------
    # WRITE
    # --------------------------------------------------------

    elif action == "WRITE":

        if not isinstance(payload_data, dict):
            raise ValueError(
                "WRITE requires a JSON object payload."
            )

        state.content_json = json.dumps(
            payload_data
        )

        result = {
            "status": "EXECUTED",
            "action": "WRITE",
            "message": "Dummy resource written.",
        }

    # --------------------------------------------------------
    # UPDATE
    # --------------------------------------------------------

    elif action == "UPDATE":

        if not isinstance(payload_data, dict):
            raise ValueError(
                "UPDATE requires a JSON object payload."
            )

        current_data.update(
            payload_data
        )

        state.content_json = json.dumps(
            current_data
        )

        result = {
            "status": "EXECUTED",
            "action": "UPDATE",
            "message": "Dummy resource updated.",
        }

    # --------------------------------------------------------
    # DELETE
    # --------------------------------------------------------

    elif action == "DELETE":

        state.content_json = "{}"

        result = {
            "status": "EXECUTED",
            "action": "DELETE",
            "message": "Dummy resource cleared.",
        }

    # --------------------------------------------------------
    # SEND
    # --------------------------------------------------------

    elif action == "SEND":

        result = {
            "status": "EXECUTED",
            "action": "SEND",
            "destination": destination,
            "message": (
                "Transfer simulated successfully. "
                "No external network operation occurred."
            ),
        }

    else:
        raise ValueError(
            f"Unsupported action: {action}"
        )

    # --------------------------------------------------------
    # Persist execution record
    # --------------------------------------------------------

    execution = ResourceExecution(
        request_id=access_request.id,
        resource_id=resource.id,
        action=action,
        result_json=json.dumps(result),
    )

    db.add(execution)

    return result
