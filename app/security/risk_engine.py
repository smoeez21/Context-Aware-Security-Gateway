
from app.config import (
    RISK_LOW_MAX,
    RISK_MEDIUM_MAX,
    RISK_HIGH_MAX,
)


# ============================================================
# RISK WEIGHTS
# ============================================================

RISK_WEIGHTS = {
    "HIGH_RESOURCE": 10,
    "CRITICAL_RESOURCE": 20,
    "EXTERNAL_DESTINATION": 15,
    "SENSITIVE_EXTERNAL_SEND": 30,
    "HIGH_FREQUENCY": 10,
    "REPEATED_RESOURCE": 5,
    "REPEATED_ACTION": 5,
    "SUSPICIOUS_ACTION_COMBINATION": 15,
    "SUSPICIOUS_SEQUENCE": 25,
    "UNUSUAL_TIME": 5,
    "MULTIPLE_DENIALS": 15,
}


# ============================================================
# DETERMINE RISK LEVEL
# ============================================================

def determine_risk_level(score: int) -> str:

    if score <= RISK_LOW_MAX:
        return "LOW"

    if score <= RISK_MEDIUM_MAX:
        return "MEDIUM"

    if score <= RISK_HIGH_MAX:
        return "HIGH"

    return "CRITICAL"


# ============================================================
# CALCULATE RISK
# ============================================================

def calculate_risk(
    authenticated: bool,
    authorized: bool,
    sensitivity_result: dict,
    context_result: dict | None,
) -> dict:

    score = 0
    factors = []

    def add_factor(
        name: str,
        points: int,
    ):
        nonlocal score

        score += points

        factors.append({
            "factor": name,
            "points": points,
        })

    # --------------------------------------------------------
    # 1. Authentication
    # --------------------------------------------------------

    if not authenticated:
        add_factor(
            "Authentication failure",
            80,
        )

    # --------------------------------------------------------
    # 2. Authorization
    # --------------------------------------------------------

    elif not authorized:
        add_factor(
            "Permission violation",
            70,
        )

    # --------------------------------------------------------
    # 3. Resource Sensitivity
    # --------------------------------------------------------

    sensitivity = sensitivity_result["sensitivity"]

    if sensitivity == "HIGH":
        add_factor(
            "HIGH sensitivity resource",
            RISK_WEIGHTS["HIGH_RESOURCE"],
        )

    elif sensitivity == "CRITICAL":
        add_factor(
            "CRITICAL sensitivity resource",
            RISK_WEIGHTS["CRITICAL_RESOURCE"],
        )

    # --------------------------------------------------------
    # 4. Context Indicators
    # --------------------------------------------------------

    context = context_result or {}

    if context.get("external_destination", False):
        add_factor(
            "External destination",
            RISK_WEIGHTS["EXTERNAL_DESTINATION"],
        )

    if context.get("sensitive_external_send", False):
        add_factor(
            "External SEND of sensitive data",
            RISK_WEIGHTS["SENSITIVE_EXTERNAL_SEND"],
        )

    if context.get("high_frequency", False):
        add_factor(
            "Abnormal request frequency",
            RISK_WEIGHTS["HIGH_FREQUENCY"],
        )

    if context.get("repeated_resource_access", False):
        add_factor(
            "Repeated resource access",
            RISK_WEIGHTS["REPEATED_RESOURCE"],
        )

    if context.get("repeated_action", False):
        add_factor(
            "Repeated action",
            RISK_WEIGHTS["REPEATED_ACTION"],
        )

    if context.get(
        "suspicious_action_combination",
        False,
    ):
        add_factor(
            "Suspicious action combination",
            RISK_WEIGHTS[
                "SUSPICIOUS_ACTION_COMBINATION"
            ],
        )

    if context.get("suspicious_sequence", False):
        add_factor(
            "Suspicious resource sequence",
            RISK_WEIGHTS["SUSPICIOUS_SEQUENCE"],
        )

    if context.get("unusual_time", False):
        add_factor(
            "Unusual request time",
            RISK_WEIGHTS["UNUSUAL_TIME"],
        )

    if context.get("multiple_recent_denials", False):
        add_factor(
            "Multiple recent denied attempts",
            RISK_WEIGHTS["MULTIPLE_DENIALS"],
        )

    # --------------------------------------------------------
    # 5. Limit Score to 100
    # --------------------------------------------------------

    score = min(score, 100)

    # --------------------------------------------------------
    # 6. Assign Risk Level
    # --------------------------------------------------------

    risk_level = determine_risk_level(score)

    # --------------------------------------------------------
    # 7. Return Explainable Risk Assessment
    # --------------------------------------------------------

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "risk_factors": factors,
    }
