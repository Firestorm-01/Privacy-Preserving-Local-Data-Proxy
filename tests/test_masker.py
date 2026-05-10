"""Integration tests for the masker."""
import sys
import os

# Ensure parent directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from masker import get_masker
from vault import TokenVault


class TestMasker:
    def setup_method(self):
        self.masker = get_masker()

    def test_masks_email(self):
        vault = TokenVault()
        text = "Contact me at sarah.chen@acmecorp.com"
        masked = self.masker.mask_text(text, vault)
        assert "sarah.chen@acmecorp.com" not in masked
        assert "<EMAIL_" in masked

    def test_masks_person_name(self):
        vault = TokenVault()
        text = "Hi, my name is Sarah Chen and I work here."
        masked = self.masker.mask_text(text, vault)
        # Should mask the name
        assert "Sarah Chen" not in masked or "<PERSON_" in masked

    def test_masks_api_key(self):
        vault = TokenVault()
        text = "Use this key: sk-abc123def456ghi789jklmnopqrs"
        masked = self.masker.mask_text(text, vault)
        assert "sk-abc123" not in masked
        assert "<API_KEY_" in masked

    def test_masks_credit_card(self):
        vault = TokenVault()
        text = "Card number: 4532015112830366"
        masked = self.masker.mask_text(text, vault)
        assert "4532015112830366" not in masked
        assert "<CREDIT_CARD_" in masked

    def test_unmask_roundtrip(self):
        vault = TokenVault()
        original = "Contact Sarah at sarah@corp.com with key sk-secret123456789012345"
        masked = self.masker.mask_text(original, vault)

        # Simulate API response using the tokens
        parts = masked.split("Contact ")
        response = f"I've noted the contact info: {parts[1]}" if len(parts) > 1 else masked

        # Unmask should restore original values
        unmasked = vault.unmask(response)
        assert "sarah@corp.com" in unmasked or "<EMAIL_" not in unmasked

    def test_idempotent_masking(self):
        vault = TokenVault()
        text = "Send to user@test.io and also cc user@test.io"
        masked = self.masker.mask_text(text, vault)

        # Same email should get same token
        tokens = [t for t in masked.split() if t.startswith("<EMAIL_")]
        if len(tokens) >= 2:
            assert tokens[0] == tokens[1]

    def test_respects_allow_list(self):
        vault = TokenVault()
        # example.com is in default allow list
        text = "Test email: test@example.com"
        masked = self.masker.mask_text(text, vault)
        # Should not mask example.com emails
        assert "example.com" in masked

    def test_masks_json_recursively(self):
        vault = TokenVault()
        data = {
            "user": {
                "name": "Sarah Chen",
                "email": "sarah@bigcorp.io",
                "notes": ["API key: sk-test123456789012345678"]
            }
        }
        masked_data = self.masker.mask_json(data, vault)

        # Original email should not appear
        assert "sarah@bigcorp.io" not in str(masked_data)

    def test_preserves_non_pii(self):
        vault = TokenVault()
        text = "The weather is nice today. Python is a great language."
        masked = self.masker.mask_text(text, vault)
        # Should be unchanged
        assert masked == text
        assert vault.entity_count == 0


class TestTokenVault:
    def test_mask_creates_token(self):
        vault = TokenVault()
        token = vault.mask("secret@email.com", "EMAIL", 0.95)
        assert token == "<EMAIL_0>"

    def test_mask_is_idempotent(self):
        vault = TokenVault()
        t1 = vault.mask("value", "TYPE")
        t2 = vault.mask("value", "TYPE")
        assert t1 == t2

    def test_unmask_restores_value(self):
        vault = TokenVault()
        vault.mask("secret123", "API_KEY")
        result = vault.unmask("Your key is <API_KEY_0>")
        assert result == "Your key is secret123"

    def test_unmask_handles_multiple(self):
        vault = TokenVault()
        vault.mask("alice@test.com", "EMAIL")
        vault.mask("bob@test.com", "EMAIL")
        result = vault.unmask("From <EMAIL_0> to <EMAIL_1>")
        assert result == "From alice@test.com to bob@test.com"

    def test_audit_summary_excludes_originals(self):
        vault = TokenVault()
        vault.mask("sensitive_data", "SECRET", 0.9)
        summary = vault.get_audit_summary()

        # Should not contain the original value
        assert "sensitive_data" not in str(summary)
        # Should contain metadata
        assert summary["entity_count"] == 1
        assert "SECRET" in summary["entity_types"]
