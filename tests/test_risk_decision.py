
from app.security.risk_engine import (
    calculate_risk,
    determine_risk_level,
)

from app.security.decision_engine import (
    make_security_decision,
)


def make_sensitivity(level):
    return {
        "sensitivity": level,
        "is_sensitive": level in {"HIGH", "CRITICAL"},
        "is_critical": level == "CRITICAL",
    }


def test_risk_levels():

    assert determine_risk_level(0) == "LOW"
    assert determine_risk_level(25) == "LOW"

    assert determine_risk_level(26) == "MEDIUM"
    assert determine_risk_level(50) == "MEDIUM"

    assert determine_risk_level(51) == "HIGH"
    assert determine_risk_level(75) == "HIGH"

    assert determine_risk_level(76) == "CRITICAL"
    assert determine_risk_level(100) == "CRITICAL"


def test_normal_access_risk():

    result = calculate_risk(
        authenticated=True,
        authorized=True,
        sensitivity_result=make_sensitivity("MEDIUM"),
        context_result={},
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "LOW"


def test_unauthorized_salary_risk():

    result = calculate_risk(
        authenticated=True,
        authorized=False,
        sensitivity_result=make_sensitivity("CRITICAL"),
        context_result=None,
    )

    assert result["risk_score"] == 90
    assert result["risk_level"] == "CRITICAL"


def test_invalid_authentication_risk():

    result = calculate_risk(
        authenticated=False,
        authorized=False,
        sensitivity_result=make_sensitivity("MEDIUM"),
        context_result=None,
    )

    assert result["risk_score"] == 80


def test_sensitive_external_transfer():

    result = calculate_risk(
        authenticated=True,
        authorized=True,
        sensitivity_result=make_sensitivity("HIGH"),
        context_result={
            "external_destination": True,
            "sensitive_external_send": True,
        },
    )

    assert result["risk_score"] == 55
    assert result["risk_level"] == "HIGH"


def test_decision_allow():

    result = make_security_decision(
        authenticated=True,
        authorized=True,
        risk_score=20,
    )

    assert result["decision"] == "ALLOW"


def test_decision_human_approval():

    result = make_security_decision(
        authenticated=True,
        authorized=True,
        risk_score=65,
    )

    assert result["decision"] == "HUMAN_APPROVAL"


def test_decision_critical_block():

    result = make_security_decision(
        authenticated=True,
        authorized=True,
        risk_score=85,
    )

    assert result["decision"] == "BLOCK"


def test_permission_denial_always_blocks():

    result = make_security_decision(
        authenticated=True,
        authorized=False,
        risk_score=20,
    )

    assert result["decision"] == "BLOCK"


def test_authentication_failure_always_blocks():

    result = make_security_decision(
        authenticated=False,
        authorized=False,
        risk_score=10,
    )

    assert result["decision"] == "BLOCK"


def test_risk_score_capped_at_100():

    result = calculate_risk(
        authenticated=True,
        authorized=True,
        sensitivity_result=make_sensitivity("CRITICAL"),
        context_result={
            "external_destination": True,
            "sensitive_external_send": True,
            "high_frequency": True,
            "repeated_resource_access": True,
            "repeated_action": True,
            "suspicious_action_combination": True,
            "suspicious_sequence": True,
            "unusual_time": True,
            "multiple_recent_denials": True,
        },
    )

    assert result["risk_score"] == 100
    assert result["risk_level"] == "CRITICAL"
