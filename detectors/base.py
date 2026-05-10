from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List
from enum import Enum


class EntityType(str, Enum):
    # Personal identifiers
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    PASSPORT = "PASSPORT"
    DRIVERS_LICENSE = "DRIVERS_LICENSE"

    # Financial
    CREDIT_CARD = "CREDIT_CARD"
    IBAN = "IBAN"
    BANK_ACCOUNT = "BANK_ACCOUNT"
    CRYPTO_WALLET = "CRYPTO_WALLET"

    # Technical/Infrastructure
    API_KEY = "API_KEY"
    JWT = "JWT"
    PASSWORD = "PASSWORD"
    SECRET = "SECRET"
    IP_ADDRESS = "IP_ADDRESS"
    MAC_ADDRESS = "MAC_ADDRESS"
    PATH = "PATH"
    URL = "URL"

    # Organizational
    ORG = "ORG"
    LOCATION = "LOCATION"

    # Medical
    MEDICAL_RECORD = "MEDICAL_RECORD"
    NPI = "NPI"  # National Provider Identifier

    # IDs
    UUID = "UUID"

    # Custom
    CUSTOM = "CUSTOM"


@dataclass
class Detection:
    """Represents a detected PII entity."""
    text: str
    entity_type: str
    start: int
    end: int
    confidence: float
    source: str  # Which detector found this
    metadata: dict = field(default_factory=dict)

    def overlaps(self, other: "Detection") -> bool:
        """Check if this detection overlaps with another."""
        return not (self.end <= other.start or self.start >= other.end)

    def contains(self, other: "Detection") -> bool:
        """Check if this detection fully contains another."""
        return self.start <= other.start and self.end >= other.end


class Detector(ABC):
    """Abstract base class for PII detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this detector."""
        pass

    @abstractmethod
    def detect(self, text: str) -> List[Detection]:
        """
        Detect PII entities in the given text.

        Args:
            text: Input text to scan

        Returns:
            List of Detection objects
        """
        pass

    def supports_entity_type(self, entity_type: str) -> bool:
        """Check if this detector can find the given entity type."""
        return True  # Override in subclasses for specificity
