"""Tests for IaC scanner."""

import pytest
from pathlib import Path
from src.iac_scanner import IaCScanner


class TestIaCScanner:
    def test_dockerfile_root_user(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM node:20\nUSER root\nCOPY . .\nCMD node app.js\n")
        scanner = IaCScanner()
        findings = scanner.scan_files([f])
        titles = [x.title for x in findings]
        assert any("root" in t.lower() for t in titles)

    def test_dockerfile_latest_tag(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:latest\nRUN apt-get update\n")
        scanner = IaCScanner()
        findings = scanner.scan_files([f])
        titles = [x.title for x in findings]
        assert any("latest" in t.lower() for t in titles)

    def test_dockerfile_secret_in_env(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nENV API_KEY=sk_live_supersecretkey12345\n")
        scanner = IaCScanner()
        findings = scanner.scan_files([f])
        titles = [x.title for x in findings]
        assert any("secret" in t.lower() for t in titles)

    def test_dockerfile_curl_pipe(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu\nRUN curl https://example.com/install.sh | bash\n")
        scanner = IaCScanner()
        findings = scanner.scan_files([f])
        titles = [x.title for x in findings]
        assert any("curl" in t.lower() or "pipe" in t.lower() for t in titles)

    def test_terraform_public_s3(self, tmp_path):
        f = tmp_path / "main.tf"
        f.write_text('resource "aws_s3_bucket" "test" {\n  public_read_access = true\n}\n')
        scanner = IaCScanner()
        findings = scanner.scan_files([f])
        titles = [x.title for x in findings]
        assert any("s3" in t.lower() or "public" in t.lower() for t in titles)

    def test_terraform_public_rds(self, tmp_path):
        f = tmp_path / "main.tf"
        f.write_text('resource "aws_db_instance" "main" {\n  publicly_accessible = true\n}\n')
        scanner = IaCScanner()
        findings = scanner.scan_files([f])
        titles = [x.title for x in findings]
        assert any("database" in t.lower() or "rds" in t.lower() or "public" in t.lower() for t in titles)

    def test_k8s_privileged(self, tmp_path):
        f = tmp_path / "deployment.yaml"
        f.write_text("apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n      securityContext:\n        privileged: true\n")
        scanner = IaCScanner()
        findings = scanner.scan_files([f])
        titles = [x.title for x in findings]
        assert any("privileged" in t.lower() for t in titles)

    def test_k8s_host_network(self, tmp_path):
        f = tmp_path / "pod.yaml"
        f.write_text("apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n    - name: app\n")
        scanner = IaCScanner()
        findings = scanner.scan_files([f])
        titles = [x.title for x in findings]
        assert any("host network" in t.lower() for t in titles)

    def test_clean_dockerfile(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12-slim\nRUN useradd app\nUSER app\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\nCOPY . .\nCMD python app.py\n")
        scanner = IaCScanner()
        findings = scanner.scan_files([f])
        # Should have no critical/high findings
        crit_high = [x for x in findings if x.severity.value in ("critical", "high")]
        assert len(crit_high) == 0

    def test_clean_terraform(self, tmp_path):
        f = tmp_path / "main.tf"
        f.write_text('resource "aws_s3_bucket" "private" {\n  bucket = "my-private-bucket"\n}\n')
        scanner = IaCScanner()
        findings = scanner.scan_files([f])
        assert len(findings) == 0
