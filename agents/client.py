
import os

import httpx


class GatewayClient:
    """
    HTTP client for the Context-Aware Security Gateway.

    All simulated agent access requests pass through
    the FastAPI gateway.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: float = 15.0,
        transport=None,
    ):

        self.base_url = (
            base_url
            or os.getenv(
                "GATEWAY_URL",
                "http://127.0.0.1:8000",
            )
        ).rstrip("/")

        self.http = httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
        )

    def access_request(
        self,
        agent_code: str,
        credential: str,
        resource_code: str,
        action: str,
        destination: str = "INTERNAL",
        payload_data: dict | None = None,
    ):

        request_body = {
            "agent_code": agent_code,
            "credential": credential,
            "resource_code": resource_code,
            "action": action,
            "destination": destination,
        }

        if payload_data is not None:
            request_body["payload_data"] = payload_data

        response = self.http.post(
            "/access-request",
            json=request_body,
        )

        response.raise_for_status()

        return response.json()

    def health_check(self):

        response = self.http.get("/health")

        response.raise_for_status()

        return response.json()

    def get_approvals(self, admin_key: str):

        response = self.http.get(
            "/approvals",
            headers={"x-admin-key": admin_key},
        )

        response.raise_for_status()

        return response.json()

    def review_approval(
        self,
        approval_id: int,
        admin_key: str,
        approve: bool,
        comment: str = "",
    ):

        action = (
            "approve" if approve else "reject"
        )

        response = self.http.post(
            f"/approvals/{approval_id}/{action}",
            headers={"x-admin-key": admin_key},
            json={"comment": comment},
        )

        response.raise_for_status()

        return response.json()

    def get_audit_logs(self, admin_key: str):

        response = self.http.get(
            "/audit-logs",
            headers={"x-admin-key": admin_key},
        )

        response.raise_for_status()

        return response.json()

    def close(self):
        self.http.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
