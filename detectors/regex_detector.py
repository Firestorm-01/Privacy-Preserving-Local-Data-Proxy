import re
from typing import List, Tuple, Pattern
from .base import Detector, Detection


class RegexDetector(Detector):
    """Pattern-based PII detection using regular expressions."""

    # Comprehensive regex patterns with confidence scores
    PATTERNS: List[Tuple[str, re.Pattern, float]] = [
        # API Keys and Secrets
        ("API_KEY", re.compile(r"\b(?:sk|pk|api|key|token|secret)[-_][A-Za-z0-9]{16,64}\b", re.I), 0.95),
        ("API_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0.98),  # AWS Access Key
        ("API_KEY", re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"), 0.98),  # AWS
        ("API_KEY", re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), 0.98),  # GitHub PAT
        ("API_KEY", re.compile(r"\bgho_[A-Za-z0-9]{36}\b"), 0.98),  # GitHub OAuth
        ("API_KEY", re.compile(r"\bghu_[A-Za-z0-9]{36}\b"), 0.98),  # GitHub User-to-server
        ("API_KEY", re.compile(r"\bghs_[A-Za-z0-9]{36}\b"), 0.98),  # GitHub Server-to-server
        ("API_KEY", re.compile(r"\bghr_[A-Za-z0-9]{36}\b"), 0.98),  # GitHub Refresh
        ("API_KEY", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,250}\b"), 0.98),  # Slack
        ("API_KEY", re.compile(r"\bxapp-[0-9]+-[A-Za-z0-9-]+\b"), 0.95),  # Slack App
        ("API_KEY", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"), 0.98),  # SendGrid
        ("API_KEY", re.compile(r"\bsq0[a-z]{3}-[A-Za-z0-9_-]{22,50}\b"), 0.95),  # Square
        ("API_KEY", re.compile(r"\brk_live_[A-Za-z0-9]{24,}\b"), 0.98),  # Stripe restricted
        ("API_KEY", re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"), 0.98),  # Stripe secret
        ("API_KEY", re.compile(r"\bpk_live_[A-Za-z0-9]{24,}\b"), 0.95),  # Stripe publishable
        ("API_KEY", re.compile(r"\bwhsec_[A-Za-z0-9]{32,}\b"), 0.95),  # Stripe webhook
        ("API_KEY", re.compile(r"\bey[A-Za-z0-9]{20,}\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), 0.90),  # Generic JWT lookalike

        # JWT (more specific)
        ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), 0.95),

        # Passwords in common formats
        ("PASSWORD", re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?", re.I), 0.85),
        ("SECRET", re.compile(r"(?:secret|private[_-]?key)\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?", re.I), 0.85),

        # Email addresses
        ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), 0.95),

        # Phone numbers (international formats)
        ("PHONE", re.compile(r"\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"), 0.85),  # US/Canada
        ("PHONE", re.compile(r"\+44\s?[0-9]{4}\s?[0-9]{6}\b"), 0.90),  # UK
        ("PHONE", re.compile(r"\+49\s?[0-9]{3,4}\s?[0-9]{6,8}\b"), 0.90),  # Germany
        ("PHONE", re.compile(r"\+33\s?[0-9]\s?[0-9]{2}\s?[0-9]{2}\s?[0-9]{2}\s?[0-9]{2}\b"), 0.90),  # France
        ("PHONE", re.compile(r"\+[0-9]{1,3}[-.\s]?[0-9]{6,14}\b"), 0.75),  # Generic international

        # SSN
        ("SSN", re.compile(r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"), 0.80),

        # Credit Cards
        ("CREDIT_CARD", re.compile(r"\b4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"), 0.90),  # Visa
        ("CREDIT_CARD", re.compile(r"\b5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"), 0.90),  # MC
        ("CREDIT_CARD", re.compile(r"\b3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}\b"), 0.90),  # Amex
        ("CREDIT_CARD", re.compile(r"\b6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"), 0.90),  # Discover

        # IBAN (international bank account)
        ("IBAN", re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b"), 0.85),

        # Crypto wallets
        ("CRYPTO_WALLET", re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"), 0.80),  # Bitcoin
        ("CRYPTO_WALLET", re.compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{39,59}\b"), 0.85),  # Bitcoin Bech32
        ("CRYPTO_WALLET", re.compile(r"\b0x[a-fA-F0-9]{40}\b"), 0.85),  # Ethereum

        # IP Addresses
        ("IP_ADDRESS", re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"), 0.90),
        ("IP_ADDRESS", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"), 0.90),  # IPv6
        ("IP_ADDRESS", re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"), 0.85),  # IPv6 compressed

        # MAC Addresses
        ("MAC_ADDRESS", re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"), 0.95),

        # File paths
        ("PATH", re.compile(r"(?<![:\w])/(?:home|Users|var|etc|opt|srv|tmp|root)/[^\s'\"<>|]+"), 0.85),
        ("PATH", re.compile(r"\b[A-Z]:\\(?:[^\s\\/:*?\"<>|]+\\)*[^\s\\/:*?\"<>|]+"), 0.90),

        # UUIDs
        ("UUID", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), 0.95),

        # Medical - NPI (National Provider Identifier)
        ("NPI", re.compile(r"\b[12][0-9]{9}\b"), 0.60),  # Low confidence, needs validation

        # Passport numbers (various formats)
        ("PASSPORT", re.compile(r"\b[A-Z]{1,2}[0-9]{6,9}\b"), 0.50),  # Generic, needs context

        # Driver's license (US formats vary by state)
        ("DRIVERS_LICENSE", re.compile(r"\b[A-Z][0-9]{7,8}\b"), 0.40),  # Generic, needs context
    ]

    @property
    def name(self) -> str:
        return "regex"

    def detect(self, text: str) -> List[Detection]:
        detections = []

        for entity_type, pattern, base_confidence in self.PATTERNS:
            for match in pattern.finditer(text):
                # Extract the matched text
                matched_text = match.group(0)

                # Handle patterns with capture groups
                if match.lastindex and match.lastindex >= 1:
                    # For password/secret patterns, extract the actual value
                    if entity_type in ("PASSWORD", "SECRET"):
                        matched_text = match.group(1)
                        start = match.start(1)
                        end = match.end(1)
                    else:
                        start = match.start()
                        end = match.end()
                else:
                    start = match.start()
                    end = match.end()

                detection = Detection(
                    text=matched_text,
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    confidence=base_confidence,
                    source=self.name,
                    metadata={"pattern": pattern.pattern[:50]}
                )
                detections.append(detection)

        return detections
