
# ============================================================
# SECURITY DECISION ENGINE
# ============================================================

def make_security_decision(
    authenticated: bool,
    authorized: bool,
    risk_score: int,
) -> dict:

    """
    Produce the final security decision.

    Possible decisions:
        ALLOW
        BLOCK
        HUMAN_APPROVAL

    Important:
        Failed authentication or authorization must
        always result in BLOCK, regardless of score.
    """

    # --------------------------------------------------------
    # 1. Authentication Failure
    # --------------------------------------------------------

    if not authenticated:
        return {
            "decision": "BLOCK",
            "reason": (
                "Access blocked because agent "
                "authentication failed."
            ),
        }

    # --------------------------------------------------------
    # 2. Authorization Failure
    # --------------------------------------------------------

    if not authorized:
        return {
            "decision": "BLOCK",
            "reason": (
                "Access blocked because the agent "
                "does not have permission."
            ),
        }

    # --------------------------------------------------------
    # 3. LOW or MEDIUM Risk
    # --------------------------------------------------------

    if risk_score <= 50:
        return {
            "decision": "ALLOW",
            "reason": (
                "Request is authenticated, authorized, "
                "and within acceptable risk limits."
            ),
        }

    # --------------------------------------------------------
    # 4. HIGH Risk
    # --------------------------------------------------------

    if risk_score <= 75:
        return {
            "decision": "HUMAN_APPROVAL",
            "reason": (
                "High-risk request requires "
                "administrator verification."
            ),
        }

    # --------------------------------------------------------
    # 5. CRITICAL Risk
    # --------------------------------------------------------

    return {
        "decision": "BLOCK",
        "reason": (
            "Critical-risk request blocked "
            "by the security gateway."
        ),
    }
