"""Configuration management for Hyperium Code-Audit."""

from __future__ import annotations
from pathlib import Path
from typing import List, Optional
import yaml
from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    paths: List[str] = Field(default=["."])
    exclude_patterns: List[str] = Field(default=[
        "node_modules/**", "vendor/**", ".git/**", "__pycache__/**",
        "venv/**", ".venv/**", "dist/**", "build/**", "*.min.js",
        "*.min.css", "*.map", "*.lock", "*.svg", "*.png", "*.jpg",
    ])
    max_file_size_kb: int = 500
    follow_symlinks: bool = False
    languages: List[str] = Field(default=[])


class ScannerConfig(BaseModel):
    pattern_scanner: bool = True
    secret_detector: bool = True
    payment_scanner: bool = True
    dep_analyzer: bool = True
    ast_engine: bool = True
    taint_analyzer: bool = True
    iac_scanner: bool = True
    api_security: bool = True
    incremental_since: str = ""
    js_ast_engine: bool = True
    payment_logic: bool = True
    verify_secrets: bool = False
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    exclude_rules: List[str] = Field(default=[])
    custom_rules_path: Optional[str] = None
    entropy_threshold: float = 4.5
    scan_env_files: bool = True
    check_epss: bool = True
    check_cisa_kev: bool = True
    dep_api_timeout: int = 10


class AnalysisConfig(BaseModel):
    asset_criticality: dict = Field(default={
        "critical_paths": ["/admin", "/login", "/api/auth", "/payment", "/checkout", "/api/users"],
        "high_paths": ["/api/", "/dashboard", "/settings", "/profile"],
        "medium_paths": ["/upload", "/export", "/download"],
    })
    frameworks: List[str] = Field(default=["owasp_top_10"])


class ReportConfig(BaseModel):
    format: str = "html"
    output_dir: str = "./reports"
    include_code_snippets: bool = True
    include_remediation: bool = True
    max_snippet_lines: int = 5


class CheckpointConfig(BaseModel):
    enabled: bool = True
    checkpoint_dir: str = ".code_audit_checkpoints"
    auto_resume: bool = True
    cleanup_on_success: bool = True


class CodeAuditConfig(BaseModel):
    project_name: str = "Untitled Project"
    scan: ScanConfig = Field(default_factory=ScanConfig)
    scanners: ScannerConfig = Field(default_factory=ScannerConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    checkpoint: CheckpointConfig = Field(default_factory=CheckpointConfig)

    @classmethod
    def from_yaml(cls, path: str) -> "CodeAuditConfig":
        content = Path(path).read_text()
        data = yaml.safe_load(content)
        if data is None:
            return cls()
        return cls.model_validate(data)

    def save_yaml(self, path: str) -> None:
        Path(path).write_text(yaml.dump(self.model_dump(), default_flow_style=False, sort_keys=False))
