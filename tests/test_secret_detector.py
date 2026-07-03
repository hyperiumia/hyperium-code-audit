"""Tests for the secret detector."""

import pytest
from pathlib import Path
from src.secret_detector import SecretDetector, calculate_entropy, redact_secret


class TestSecretDetector:
    def test_detect_aws_key(self, tmp_source_dir):
        detector = SecretDetector()
        findings = detector.scan_file(tmp_source_dir / ".env")
        aws_findings = [f for f in findings if "AWS" in f.secret_type]
        assert len(aws_findings) >= 1

    def test_detect_stripe_key(self, tmp_source_dir):
        detector = SecretDetector()
        findings = detector.scan_file(tmp_source_dir / "app.js")
        stripe_findings = [f for f in findings if "STRIPE" in f.secret_type]
        assert len(stripe_findings) >= 1
        assert any(f.is_live_key for f in stripe_findings)

    def test_detect_database_url(self, tmp_source_dir):
        detector = SecretDetector()
        findings = detector.scan_file(tmp_source_dir / ".env")
        db_findings = [f for f in findings if "DATABASE" in f.secret_type]
        assert len(db_findings) >= 1

    def test_detect_mercadopago(self, tmp_source_dir):
        detector = SecretDetector()
        findings = detector.scan_file(tmp_source_dir / "app.js")
        mp_findings = [f for f in findings if "MERCADOPAGO" in f.secret_type]
        assert len(mp_findings) >= 1

    def test_entropy_calculation(self):
        assert calculate_entropy("aaaa") < calculate_entropy("aB3$")
        assert calculate_entropy("sk_test_EXAMPLE_FAKE_123") > 3.0

    def test_redact_secret(self):
        result = redact_secret("sk_test_EXAMPLE_NOT_REAL_KEY_1234567890")
        assert result.startswith("sk_l")
        assert result.endswith("m3n4")
        assert "*" in result


class TestEntropy:
    def test_low_entropy(self):
        assert calculate_entropy("aaaaaaaaaa") < 1.0

    def test_high_entropy(self):
        assert calculate_entropy("aB3$xY9!mN2@") > 3.0
