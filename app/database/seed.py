import hashlib

from app.database.database import (
    SessionLocal,
    create_database
)

from app.database.models import (
    Agent,
    Policy,
    Resource
)


def hash_credential(credential: str) -> str:
    return hashlib.sha256(
        credential.encode("utf-8")
    ).hexdigest()


def seed_agents(db):

    agents = [
        {
            "agent_code": "AGENT-SALES-001",
            "name": "Sales Agent",
            "department": "Sales",
            "role": "Sales Representative",
            "status": "ACTIVE",
            "credential": "sales-demo-key"
        },
        {
            "agent_code": "AGENT-HR-001",
            "name": "HR Agent",
            "department": "HR",
            "role": "HR Representative",
            "status": "ACTIVE",
            "credential": "hr-demo-key"
        },
        {
            "agent_code": "AGENT-FIN-001",
            "name": "Finance Agent",
            "department": "Finance",
            "role": "Finance Representative",
            "status": "ACTIVE",
            "credential": "finance-demo-key"
        },
        {
            "agent_code": "AGENT-RES-001",
            "name": "Research Agent",
            "department": "Research",
            "role": "Research Representative",
            "status": "ACTIVE",
            "credential": "research-demo-key"
        }
    ]

    for item in agents:

        existing = (
            db.query(Agent)
            .filter(
                Agent.agent_code
                == item["agent_code"]
            )
            .first()
        )

        if existing:
            continue

        agent = Agent(
            agent_code=item["agent_code"],
            name=item["name"],
            department=item["department"],
            role=item["role"],
            status=item["status"],
            credential_hash=hash_credential(
                item["credential"]
            )
        )

        db.add(agent)

    db.commit()


def seed_resources(db):

    resources = [
        {
            "resource_code": "RES-SALES",
            "name": "Sales Data",
            "resource_type": "FILE",
            "sensitivity": "MEDIUM",
            "description": "Synthetic sales information."
        },
        {
            "resource_code": "RES-CUSTOMERS",
            "name": "Customer Data",
            "resource_type": "DATABASE",
            "sensitivity": "HIGH",
            "description": "Synthetic customer information."
        },
        {
            "resource_code": "RES-EMPLOYEES",
            "name": "Employee Data",
            "resource_type": "DATABASE",
            "sensitivity": "HIGH",
            "description": "Synthetic employee information."
        },
        {
            "resource_code": "RES-SALARY",
            "name": "Employee Salary",
            "resource_type": "DATABASE",
            "sensitivity": "CRITICAL",
            "description": "Synthetic employee salary data."
        },
        {
            "resource_code": "RES-RESEARCH",
            "name": "Research Notes",
            "resource_type": "FILE",
            "sensitivity": "MEDIUM",
            "description": "Synthetic research information."
        },
        {
            "resource_code": "RES-FINANCE",
            "name": "Financial Records",
            "resource_type": "DATABASE",
            "sensitivity": "CRITICAL",
            "description": "Synthetic organizational financial data."
        },
        {
            "resource_code": "RES-CREDENTIALS",
            "name": "Credentials",
            "resource_type": "FILE",
            "sensitivity": "CRITICAL",
            "description": "Synthetic credential information."
        }
    ]

    for item in resources:

        existing = (
            db.query(Resource)
            .filter(
                Resource.resource_code
                == item["resource_code"]
            )
            .first()
        )

        if existing:
            continue

        resource = Resource(**item)

        db.add(resource)

    db.commit()


def add_policy(
    db,
    agent,
    resource,
    action,
    destination,
    effect,
    description
):

    existing = (
        db.query(Policy)
        .filter(
            Policy.agent_id == agent.id,
            Policy.resource_id == resource.id,
            Policy.action == action,
            Policy.destination == destination
        )
        .first()
    )

    if existing:
        return

    policy = Policy(
        agent_id=agent.id,
        resource_id=resource.id,
        action=action,
        destination=destination,
        effect=effect,
        description=description
    )

    db.add(policy)


def seed_policies(db):

    sales = (
        db.query(Agent)
        .filter(Agent.agent_code == "AGENT-SALES-001")
        .first()
    )

    hr = (
        db.query(Agent)
        .filter(Agent.agent_code == "AGENT-HR-001")
        .first()
    )

    finance = (
        db.query(Agent)
        .filter(Agent.agent_code == "AGENT-FIN-001")
        .first()
    )

    research = (
        db.query(Agent)
        .filter(Agent.agent_code == "AGENT-RES-001")
        .first()
    )

    sales_data = (
        db.query(Resource)
        .filter(Resource.resource_code == "RES-SALES")
        .first()
    )

    customers = (
        db.query(Resource)
        .filter(Resource.resource_code == "RES-CUSTOMERS")
        .first()
    )

    employees = (
        db.query(Resource)
        .filter(Resource.resource_code == "RES-EMPLOYEES")
        .first()
    )

    salary = (
        db.query(Resource)
        .filter(Resource.resource_code == "RES-SALARY")
        .first()
    )

    research_notes = (
        db.query(Resource)
        .filter(Resource.resource_code == "RES-RESEARCH")
        .first()
    )

    financial_records = (
        db.query(Resource)
        .filter(Resource.resource_code == "RES-FINANCE")
        .first()
    )

    credentials = (
        db.query(Resource)
        .filter(Resource.resource_code == "RES-CREDENTIALS")
        .first()
    )

    # --------------------------------------------------------
    # SALES POLICIES
    # --------------------------------------------------------

    add_policy(
        db,
        sales,
        sales_data,
        "READ",
        "INTERNAL",
        "ALLOW",
        "Sales agent may read sales data."
    )

    add_policy(
        db,
        sales,
        sales_data,
        "WRITE",
        "INTERNAL",
        "ALLOW",
        "Sales agent may write sales data."
    )

    add_policy(
        db,
        sales,
        sales_data,
        "UPDATE",
        "INTERNAL",
        "ALLOW",
        "Sales agent may update sales data."
    )

    add_policy(
        db,
        sales,
        customers,
        "READ",
        "INTERNAL",
        "ALLOW",
        "Sales agent may read customer data internally."
    )

    add_policy(
        db,
        sales,
        customers,
        "SEND",
        "EXTERNAL",
        "ALLOW",
        (
            "Policy-level access is allowed, but the "
            "risk engine may escalate external transfer."
        )
    )

    add_policy(
        db,
        sales,
        salary,
        "READ",
        "INTERNAL",
        "DENY",
        "Sales agent cannot access employee salaries."
    )

    add_policy(
        db,
        sales,
        credentials,
        "READ",
        "INTERNAL",
        "DENY",
        "Sales agent cannot access credentials."
    )

    # --------------------------------------------------------
    # HR POLICIES
    # --------------------------------------------------------

    add_policy(
        db,
        hr,
        employees,
        "READ",
        "INTERNAL",
        "ALLOW",
        "HR agent may read employee data."
    )

    add_policy(
        db,
        hr,
        employees,
        "UPDATE",
        "INTERNAL",
        "ALLOW",
        "HR agent may update employee data."
    )

    add_policy(
        db,
        hr,
        salary,
        "READ",
        "INTERNAL",
        "ALLOW",
        "HR agent may read salary information."
    )

    add_policy(
        db,
        hr,
        credentials,
        "READ",
        "INTERNAL",
        "DENY",
        "HR agent cannot access credentials."
    )

    # --------------------------------------------------------
    # FINANCE POLICIES
    # --------------------------------------------------------

    add_policy(
        db,
        finance,
        financial_records,
        "READ",
        "INTERNAL",
        "ALLOW",
        "Finance agent may read financial records."
    )

    add_policy(
        db,
        finance,
        financial_records,
        "WRITE",
        "INTERNAL",
        "ALLOW",
        "Finance agent may write financial records."
    )

    add_policy(
        db,
        finance,
        financial_records,
        "UPDATE",
        "INTERNAL",
        "ALLOW",
        "Finance agent may update financial records."
    )

    add_policy(
        db,
        finance,
        financial_records,
        "SEND",
        "EXTERNAL",
        "DENY",
        "Financial records cannot be sent externally."
    )

    add_policy(
        db,
        finance,
        credentials,
        "READ",
        "INTERNAL",
        "DENY",
        "Finance agent cannot access credentials."
    )

    # --------------------------------------------------------
    # RESEARCH POLICIES
    # --------------------------------------------------------

    add_policy(
        db,
        research,
        research_notes,
        "READ",
        "INTERNAL",
        "ALLOW",
        "Research agent may read research notes."
    )

    add_policy(
        db,
        research,
        research_notes,
        "WRITE",
        "INTERNAL",
        "ALLOW",
        "Research agent may write research notes."
    )

    add_policy(
        db,
        research,
        research_notes,
        "UPDATE",
        "INTERNAL",
        "ALLOW",
        "Research agent may update research notes."
    )

    add_policy(
        db,
        research,
        financial_records,
        "DELETE",
        "INTERNAL",
        "DENY",
        "Research agent cannot delete financial records."
    )

    add_policy(
        db,
        research,
        credentials,
        "READ",
        "INTERNAL",
        "DENY",
        "Research agent cannot access credentials."
    )

    db.commit()


def main():

    print("Creating database tables...")

    create_database()

    db = SessionLocal()

    try:

        print("Creating agents...")
        seed_agents(db)

        print("Creating resources...")
        seed_resources(db)

        print("Creating policies...")
        seed_policies(db)

        print()
        print("Database successfully initialized.")
        print()

        print(
            f"Agents: "
            f"{db.query(Agent).count()}"
        )

        print(
            f"Resources: "
            f"{db.query(Resource).count()}"
        )

        print(
            f"Policies: "
            f"{db.query(Policy).count()}"
        )

    finally:
        db.close()


if __name__ == "__main__":
    main()