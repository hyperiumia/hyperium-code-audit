"""Tests for payment logic analyzer."""

import pytest
from pathlib import Path
from src.payment_logic import PaymentLogicAnalyzer


class TestPaymentLogicAnalyzer:
    def test_detect_missing_webhook_verification(self, tmp_path):
        f = tmp_path / "webhooks.py"
        f.write_text(
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/stripe-webhook', methods=['POST'])\n"
            "def stripe_webhook():\n"
            "    payload = request.get_json()\n"
            "    handle_payment(payload)\n"
        )
        analyzer = PaymentLogicAnalyzer()
        findings = analyzer.scan_file(f)
        webhook_findings = [x for x in findings if "webhook" in x.title.lower() and "signature" in x.title.lower()]
        assert len(webhook_findings) >= 1

    def test_no_finding_when_verified(self, tmp_path):
        f = tmp_path / "webhooks_verified.py"
        f.write_text(
            "import stripe\n"
            "from flask import Flask, request\n\n"
            "@app.route('/stripe-webhook', methods=['POST'])\n"
            "def stripe_webhook():\n"
            "    payload = request.data\n"
            "    sig = request.headers.get('Stripe-Signature')\n"
            "    event = stripe.Webhook.construct_event(payload, sig, endpoint_secret)\n"
        )
        analyzer = PaymentLogicAnalyzer()
        findings = analyzer.scan_file(f)
        webhook_findings = [x for x in findings if "signature" in x.title.lower()]
        assert len(webhook_findings) == 0

    def test_detect_missing_idempotency(self, tmp_path):
        f = tmp_path / "charges.py"
        f.write_text(
            "import stripe\n\n"
            "def create_charge(amount, token):\n"
            "    charge = stripe.Charge.create(\n"
            "        amount=amount,\n"
            "        currency='usd',\n"
            "        source=token,\n"
            "    )\n"
        )
        analyzer = PaymentLogicAnalyzer()
        findings = analyzer.scan_file(f)
        idem_findings = [x for x in findings if "idempotency" in x.title.lower()]
        assert len(idem_findings) >= 1

    def test_detect_client_amount(self, tmp_path):
        f = tmp_path / "checkout.py"
        f.write_text(
            "from flask import request\n"
            "import stripe\n\n"
            "def checkout():\n"
            "    amount = request.json.get('amount')\n"
            "    stripe.PaymentIntent.create(amount=amount)\n"
        )
        analyzer = PaymentLogicAnalyzer()
        findings = analyzer.scan_file(f)
        amount_findings = [x for x in findings if "amount" in x.title.lower()]
        assert len(amount_findings) >= 1

    def test_no_findings_clean_code(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text(
            "import hashlib\n\n"
            "def hash_data(data):\n"
            "    return hashlib.sha256(data.encode()).hexdigest()\n"
        )
        analyzer = PaymentLogicAnalyzer()
        findings = analyzer.scan_file(f)
        assert len(findings) == 0
