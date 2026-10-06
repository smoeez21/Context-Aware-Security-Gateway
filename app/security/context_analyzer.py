from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.database.models import AccessRequest


def analyze_context(
    db: Session,
    agent_id: int,
    resource_id: int,
    action: str,
    destination: str
):
    """
    Analyze the recent behavior of an authenticated and
    authorized AI agent.

    This function does NOT calculate the final risk score.
    It only produces contextual security indicators.

    Risk scoring will be performed in Phase 6.
    """

    # =========================================================
    # 1. Current Time
    # =========================================================

    now = datetime.now(timezone.utc)

    one_minute_ago = now - timedelta(minutes=1)
    five_minutes_ago = now - timedelta(minutes=5)

    # =========================================================
    # 2. Get Recent Agent Requests
    # =========================================================

    recent_requests = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.agent_id == agent_id,
            AccessRequest.requested_at >= five_minutes_ago
        )
        .order_by(
            AccessRequest.requested_at.desc()
        )
        .all()
    )

    # =========================================================
    # 3. Count Requests During Last Minute
    # =========================================================

    requests_last_minute = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.agent_id == agent_id,
            AccessRequest.requested_at >= one_minute_ago
        )
        .count()
    )

    # IMPORTANT:
    # The current request has not yet been saved when context
    # analysis runs.
    #
    # Therefore 9 previous requests + current request = 10.
    #
    # We consider 10 or more requests/minute high frequency.

    high_frequency = (
        requests_last_minute >= 9
    )

    # =========================================================
    # 4. Recent Request Count
    # =========================================================

    recent_request_count = len(
        recent_requests
    )

    # =========================================================
    # 5. External Destination Detection
    # =========================================================

    external_destination = (
        destination == "EXTERNAL"
    )

    # =========================================================
    # 6. Repeated Resource Access
    # =========================================================

    repeated_resource_count = sum(
        1
        for request in recent_requests
        if request.resource_id == resource_id
    )

    # Four previous accesses + current = fifth request

    repeated_resource_access = (
        repeated_resource_count >= 4
    )

    # =========================================================
    # 7. Repeated Action Detection
    # =========================================================

    repeated_action_count = sum(
        1
        for request in recent_requests
        if request.action == action
    )

    repeated_action = (
        repeated_action_count >= 4
    )

    # =========================================================
    # 8. Recent Actions
    # =========================================================

    recent_actions = [
        request.action
        for request in recent_requests[:10]
    ]

    # =========================================================
    # 9. Suspicious Action Combination
    # =========================================================
    #
    # Example:
    #
    # READ sensitive information
    #        ↓
    # SEND externally
    #
    # The current action is considered as part of the
    # sequence even though it has not yet been written
    # to the database.
    # =========================================================

    suspicious_action_combination = False

    if (
        action == "SEND"
        and destination == "EXTERNAL"
        and "READ" in recent_actions
    ):
        suspicious_action_combination = True

    # =========================================================
    # 10. Get Recent Resource Names
    # =========================================================

    recent_resource_names = []

    for request in recent_requests[:10]:

        if request.resource is not None:
            recent_resource_names.append(
                request.resource.name
            )

    # =========================================================
    # 11. Suspicious Resource Sequence
    # =========================================================
    #
    # Project demonstration scenario:
    #
    # Customer Data
    #       ↓
    # Credentials
    #       ↓
    # External Transfer
    #
    # Access to Credentials may have been BLOCKED.
    # It is still part of request history and therefore
    # remains useful security context.
    # =========================================================

    has_customer_data = (
        "Customer Data"
        in recent_resource_names
    )

    has_credentials = (
        "Credentials"
        in recent_resource_names
    )

    suspicious_sequence = (
        has_customer_data
        and has_credentials
        and action == "SEND"
        and destination == "EXTERNAL"
    )

    # =========================================================
    # 12. Request-Time Analysis
    # =========================================================
    #
    # Demonstration assumption:
    #
    # Requests between 23:00 and 05:59 UTC are considered
    # unusual.
    #
    # This is a contextual indicator only. It does NOT mean
    # the request is automatically malicious.
    # =========================================================

    current_hour = now.hour

    unusual_time = (
        current_hour < 6
        or current_hour >= 23
    )

    # =========================================================
    # 13. Count Recently Blocked Requests
    # =========================================================

    recent_denied_count = sum(
        1
        for request in recent_requests
        if request.decision == "BLOCK"
    )

    # =========================================================
    # 14. Multiple Recent Denials
    # =========================================================
    #
    # Three or more recently blocked attempts may indicate
    # probing or abnormal behavior.
    # =========================================================

    multiple_recent_denials = (
        recent_denied_count >= 3
    )

    # =========================================================
    # 15. Overall Unusual Activity Indicator
    # =========================================================

    unusual_activity = any([
        high_frequency,
        repeated_resource_access,
        repeated_action,
        suspicious_action_combination,
        suspicious_sequence,
        unusual_time,
        multiple_recent_denials
    ])

    # =========================================================
    # 16. Return Context Analysis
    # =========================================================

    return {
        "requests_last_minute":
            requests_last_minute,

        "recent_request_count":
            recent_request_count,

        "high_frequency":
            high_frequency,

        "external_destination":
            external_destination,

        "repeated_resource_access":
            repeated_resource_access,

        "repeated_action":
            repeated_action,

        "suspicious_action_combination":
            suspicious_action_combination,

        "suspicious_sequence":
            suspicious_sequence,

        "unusual_time":
            unusual_time,

        "recent_denied_count":
            recent_denied_count,

        "multiple_recent_denials":
            multiple_recent_denials,

        "unusual_activity":
            unusual_activity
    }