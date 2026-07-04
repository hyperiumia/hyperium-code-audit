"""Tests for the secret verifier."""

import pytest
from src.secret_verifier import verify_secret_format, calculate_entropy


class TestSecretVerifier:
    def test_valid_aws_key_format(self):
        result = verify_secret_format("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
        assert result.is_valid_format is True

    def test_invalid_aws_key_format(self):
        result = verify_secret_format("AWS_ACCESS_KEY", "NOT_A_VALID_KEY")
        assert result.is_valid_format is False
        assert result.confidence_boost < 0

    def test_valid_github_token(self):
        result = verify_secret_format("GITHUB_TOKEN", "ghp_" + "a" * 36)
        assert result.is_valid_format is True

    def test_short_key_rejected(self):
        result = verify_secret_format("GITHUB_TOKEN", "ghp_short")
        assert result.is_valid_format is False

    def test_high_entropy_boosts(self):
        # Must use [A-Za-z0-9] chars only for OPENAI_KEY format + high entropy
        result = verify_secret_format("OPENAI_KEY", "sk-xY3mN7pQ2bR5kL8wZ4aD6cEfGhJ1K2L3M4N5O6P7Q8R9S0T1")
        assert result.is_valid_format is True
        assert result.is_high_entropy is True

    def test_low_entropy_penalizes(self):
        result = verify_secret_format("STRIPE_SECRET_KEY", "sk_live_aaaaaaaaaaaaaaaa")
        assert result.is_high_entropy is False

    def test_private_key_detected(self):
        result = verify_secret_format("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----")
        assert result.is_valid_format is True

    def test_unknown_type_returns_neutral(self):
        result = verify_secret_format("UNKNOWN_TYPE", "some_value")
        assert result.is_valid_format is False
        assert result.confidence_boost == 0.0

    def test_entropy_calculation(self):
        assert calculate_entropy("aaaa") < calculate_entropy("xY3$")
        assert calculate_entropy("") == 0.0
