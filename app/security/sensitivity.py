def analyze_resource_sensitivity(resource):

    sensitivity = resource.sensitivity.upper()

    sensitivity_weights = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    weight = sensitivity_weights.get(
        sensitivity,
        1
    )

    return {
        "sensitivity": sensitivity,
        "sensitivity_weight": weight,
        "is_sensitive": sensitivity in {
            "HIGH",
            "CRITICAL"
        },
        "is_critical": sensitivity == "CRITICAL"
    }