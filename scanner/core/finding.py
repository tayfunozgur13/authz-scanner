import enum

from pydantic import BaseModel

from scanner.core.evidence import HttpEvidence


class VulnerabilityClass(str, enum.Enum):
    BOLA = "BOLA"
    BFLA = "BFLA"
    MASS_ASSIGNMENT = "Mass Assignment"
    EXCESSIVE_DATA_EXPOSURE = "Excessive Data Exposure"
    PRIVILEGE_ESCALATION = "Privilege Escalation"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    title: str
    vulnerability_class: VulnerabilityClass
    severity: Severity
    endpoint: str
    method: str
    identity_name: str
    description: str
    business_impact: str
    recommendation: str
    evidence: list[HttpEvidence]

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)
