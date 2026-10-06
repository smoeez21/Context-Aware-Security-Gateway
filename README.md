# Context-Aware Security Gateway for Autonomous AI Agents

## Project Overview

This project implements a security gateway that controls access
between autonomous AI agents and organizational resources.

The gateway performs:

- Agent authentication
- Authorization
- Resource sensitivity analysis
- Context analysis
- Risk assessment
- Security decision making
- Human approval
- Resource execution
- Audit logging
- Monitoring

## Security Decisions

The gateway supports:

- ALLOW
- BLOCK
- HUMAN APPROVAL

## Technology Stack

- Python
- FastAPI
- SQLite
- SQLAlchemy
- Pydantic
- Uvicorn
- Streamlit
- Pytest
- Git/GitHub

## Run

Activate the virtual environment and run:

```bash
uvicorn app.main:app --reload