"""Tests for individual detectors."""
import sys
import os

# Ensure parent directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from detectors import RegexDetector, ChecksumValidator


class TestRegexDetector:
    def setup_method(self):
        self.detector = RegexDetector()

    def test_detects_aws_key(self):
        text = "My AWS key is AKIAIOSFODNN7EXAMPLE"
        detections = self.detector.detect(text)
        assert any(d.entity_type == "API_KEY" and "AKIA" in d.text for d in detections)

    def test_detects_github_token(self):
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
        detections = self.detector.detect(text)
        assert any(d.entity_type == "API_KEY" and d.text.startswith("ghp_") for d in detections)

    def test_detects_email(self):
        text = "Contact me at john.doe@company.example.com"
        detections = self.detector.detect(text)
        assert any(d.entity_type == "EMAIL" for d in detections)

    def test_detects_credit_card(self):
        text = "Card: 4532015112830366"
        detections = self.detector.detect(text)
        assert any(d.entity_type == "CREDIT_CARD" for d in detections)

    def test_detects_ipv4(self):
        text = "Server IP: 192.168.1.100"
        detections = self.detector.detect(text)
        assert any(d.entity_type == "IP_ADDRESS" for d in detections)

    def test_detects_unix_path(self):
        text = "Log file: /home/user/logs/app.log"
        detections = self.detector.detect(text)
        assert any(d.entity_type == "PATH" for d in detections)

    def test_detects_windows_path(self):
        text = r"Config at C:\Users\Admin\config.ini"
        detections = self.detector.detect(text)
        assert any(d.entity_type == "PATH" for d in detections)

    def test_detects_uuid(self):
        text = "ID: 550e8400-e29b-41d4-a716-446655440000"
        detections = self.detector.detect(text)
        assert any(d.entity_type == "UUID" for d in detections)

    def test_detects_jwt(self):
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        detections = self.detector.detect(text)
        assert any(d.entity_type == "JWT" for d in detections)


class TestChecksumValidator:
    def test_valid_credit_card_luhn(self):
        # Valid Visa test number
        is_valid, mult = ChecksumValidator.validate("4532015112830366", "CREDIT_CARD")
        assert is_valid
        assert mult >= 0.9

    def test_invalid_credit_card_luhn(self):
        # Invalid checksum
        is_valid, mult = ChecksumValidator.validate("4532015112830367", "CREDIT_CARD")
        assert not is_valid
        assert mult < 0.5

    def test_valid_ssn(self):
        is_valid, mult = ChecksumValidator.validate("123-45-6789", "SSN")
        assert is_valid

    def test_invalid_ssn_area(self):
        # Area 666 is invalid
        is_valid, mult = ChecksumValidator.validate("666-45-6789", "SSN")
        assert not is_valid

    def test_valid_iban(self):
        # German IBAN
        is_valid, mult = ChecksumValidator.validate("DE89370400440532013000", "IBAN")
        assert is_valid
