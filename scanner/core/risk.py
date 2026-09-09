from scanner.core.finding import Severity, VulnerabilityClass


SEVERITY_SCORES = {
    Severity.LOW: 20,
    Severity.MEDIUM: 50,
    Severity.HIGH: 80,
    Severity.CRITICAL: 95,
}


def score_for_severity(severity: Severity) -> int:
    return SEVERITY_SCORES[severity]


def clamp_risk_score(score: int) -> int:
    return max(0, min(100, score))


def severity_from_score(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    return Severity.LOW


def infer_default_severity(
    vulnerability_class: VulnerabilityClass,
    method: str,
    endpoint: str,
) -> Severity:
    normalized_method = method.upper()
    normalized_endpoint = endpoint.lower()

    if vulnerability_class == VulnerabilityClass.PRIVILEGE_ESCALATION:
        return Severity.CRITICAL

    if vulnerability_class == VulnerabilityClass.BFLA:
        if any(keyword in normalized_endpoint for keyword in ("refund", "admin", "approve")):
            return Severity.CRITICAL
        if any(keyword in normalized_endpoint for keyword in ("close", "delete", "disable")):
            return Severity.HIGH
        return Severity.HIGH

    if vulnerability_class == VulnerabilityClass.MASS_ASSIGNMENT:
        if any(keyword in normalized_endpoint for keyword in ("orders", "payments", "billing")):
            return Severity.CRITICAL
        return Severity.HIGH

    if vulnerability_class == VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE:
        if any(keyword in normalized_endpoint for keyword in ("token", "auth", "users/me")):
            return Severity.CRITICAL
        if any(keyword in normalized_endpoint for keyword in ("support", "invoice", "billing")):
            return Severity.HIGH
        return Severity.MEDIUM

    if vulnerability_class == VulnerabilityClass.BOLA:
        if normalized_method in {"DELETE", "PUT", "PATCH", "POST"}:
            return Severity.CRITICAL
        if any(keyword in normalized_endpoint for keyword in ("invoice", "billing", "payment")):
            return Severity.CRITICAL
        return Severity.HIGH

    if vulnerability_class == VulnerabilityClass.UNAUTHENTICATED_ACCESS:
        if normalized_method in {"DELETE", "PUT", "PATCH", "POST"}:
            return Severity.CRITICAL
        if any(keyword in normalized_endpoint for keyword in ("admin", "users", "invoice", "billing")):
            return Severity.HIGH
        return Severity.MEDIUM

    return Severity.MEDIUM


def resolve_risk(
    vulnerability_class: VulnerabilityClass,
    method: str,
    endpoint: str,
    severity_override: Severity | None = None,
    risk_score_override: int | None = None,
) -> tuple[Severity, int]:
    if risk_score_override is not None:
        score = clamp_risk_score(risk_score_override)
        severity = severity_override or severity_from_score(score)
        return severity, score

    severity = severity_override or infer_default_severity(
        vulnerability_class=vulnerability_class,
        method=method,
        endpoint=endpoint,
    )
    return severity, score_for_severity(severity)
