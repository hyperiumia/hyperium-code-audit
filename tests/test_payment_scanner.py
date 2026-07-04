"""Tests for the payment scanner."""

import pytest
from pathlib import Path
from src.payment_scanner import PaymentScanner, _luhn_check


class TestPaymentScanner:
    def test_detect_stripe_live(self, tmp_source_dir):
        scanner = PaymentScanner()
        findings = scanner.scan_file(tmp_source_dir / "app.js")
        stripe = [f for f in findings if f.gateway == "Stripe"]
        assert len(stripe) >= 1

    def test_detect_mercadopago(self, tmp_source_dir):
        scanner = PaymentScanner()
        findings = scanner.scan_file(tmp_source_dir / "app.js")
        mp = [f for f in findings if f.gateway == "MercadoPago"]
        assert len(mp) >= 1

    def test_pci_violation_flagged(self, tmp_source_dir):
        scanner = PaymentScanner()
        findings = scanner.scan_file(tmp_source_dir / "app.js")
        assert any(f.pci_violation for f in findings)

    def test_luhn_validation(self):
        assert _luhn_check("4111111111111111") is True
        assert _luhn_check("1234567890") is False
