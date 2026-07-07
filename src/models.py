"""Data models for Hyperium Code-Audit."""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}[self.value]

    @property
    def color(self) -> str:
        return {"critical": "red", "high": "orange", "medium": "yellow", "low": "green", "info": "blue"}[self.value]


class FindingCategory(str, Enum):
    INJECTION = "injection"
    XSS = "xss"
    SSRF = "ssrf"
    PATH_TRAVERSAL = "path_traversal"
    BROKEN_AUTH = "broken_auth"
    CRYPTO_FAILURE = "crypto_failure"
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    SECURITY_MISCONFIG = "security_misconfig"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    LOGGING_FAILURE = "logging_failure"
    PAYMENT_EXPOSURE = "payment_exposure"
    INSECURE_DIRECT_REF = "insecure_direct_ref"
    COMMAND_INJECTION = "command_injection"
    TEMPLATE_INJECTION = "template_injection"
    XXE = "xxe"
    OPEN_REDIRECT = "open_redirect"
    INFO_DISCLOSURE = "info_disclosure"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    PHP = "php"
    JAVA = "java"
    GO = "go"
    CSHARP = "csharp"
    RUBY = "ruby"
    HTML = "html"
    UNKNOWN = "unknown"
    DOCKERFILE = "dockerfile"
    TERRAFORM = "terraform"
    KUBERNETES = "kubernetes"
    YAML = "yaml"
    SHELL = "shell"


class ComplianceFramework(str, Enum):
    OWASP_TOP_10 = "owasp_top_10"
    PCI_DSS = "pci_dss"
    NIST_800_53 = "nist_800_53"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    CWE = "cwe"


class ComplianceStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: f"F-{uuid.uuid4().hex[:8]}")
    rule_id: str
    title: str
    category: FindingCategory
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    file_path: str
    line_number: int = 0
    column: int = 0
    end_line: int = 0
    code_snippet: str = ""
    language: Language = Language.UNKNOWN
    cwe_id: str = ""
    owasp_id: str = ""
    description: str = ""
    remediation: str = ""
    impact: str = ""
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    epss_score: Optional[float] = None
    in_cisa_kev: bool = False
    is_false_positive: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecretFinding(BaseModel):
    id: str = Field(default_factory=lambda: f"S-{uuid.uuid4().hex[:8]}")
    secret_type: str
    file_path: str
    line_number: int
    column: int = 0
    redacted_value: str
    confidence: float = Field(ge=0.0, le=1.0)
    is_live_key: bool = False
    language: Language = Language.UNKNOWN
    entropy: float = 0.0
    description: str = ""
    remediation: str = ""


class PaymentFinding(BaseModel):
    id: str = Field(default_factory=lambda: f"P-{uuid.uuid4().hex[:8]}")
    gateway: str
    key_type: str
    file_path: str
    line_number: int
    redacted_value: str
    severity: Severity = Severity.CRITICAL
    description: str = ""
    remediation: str = ""
    pci_violation: bool = True


class DepVulnerability(BaseModel):
    id: str = Field(default_factory=lambda: f"D-{uuid.uuid4().hex[:8]}")
    package_name: str
    current_version: str
    fixed_version: str = ""
    ecosystem: str
    cve_id: str = ""
    ghsa_id: str = ""
    cvss_score: float = 0.0
    epss_score: float = 0.0
    in_cisa_kev: bool = False
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""
    references: List[str] = Field(default_factory=list)
    is_transitive: bool = False


class RiskScore(BaseModel):
    overall_score: float = Field(ge=0.0, le=100.0)
    risk_level: Severity = Severity.INFO
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    total_findings: int = 0
    top_categories: List[Dict[str, Any]] = Field(default_factory=list)
    top_files: List[Dict[str, Any]] = Field(default_factory=list)
    scoring_factors: Dict[str, float] = Field(default_factory=dict)


class ComplianceMapping(BaseModel):
    framework: ComplianceFramework
    requirement_id: str
    requirement_title: str
    status: ComplianceStatus
    findings: List[str] = Field(default_factory=list)
    gap_description: str = ""


class ComplianceReport(BaseModel):
    framework: ComplianceFramework
    total_requirements: int = 0
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    not_applicable: int = 0
    compliance_percentage: float = 0.0
    mappings: List[ComplianceMapping] = Field(default_factory=list)
    gaps: List[str] = Field(default_factory=list)


class ScanStats(BaseModel):
    total_files_discovered: int = 0
    total_files_scanned: int = 0
    total_lines_scanned: int = 0
    scan_duration_seconds: float = 0.0
    files_by_language: Dict[str, int] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    skipped_files: int = 0


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: f"SCAN-{uuid.uuid4().hex[:12]}")
    tool_version: str = "1.0.0"
    target_path: str
    started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str = ""
    findings: List[Finding] = Field(default_factory=list)
    secrets: List[SecretFinding] = Field(default_factory=list)
    payment_findings: List[PaymentFinding] = Field(default_factory=list)
    dep_vulnerabilities: List[DepVulnerability] = Field(default_factory=list)
    risk_score: Optional[RiskScore] = None
    compliance_reports: List[ComplianceReport] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)

    @property
    def total_findings(self) -> int:
        return len(self.findings) + len(self.secrets) + len(self.payment_findings) + len(self.dep_vulnerabilities)

    @property
    def has_critical(self) -> bool:
        return self.risk_score is not None and self.risk_score.critical_count > 0
