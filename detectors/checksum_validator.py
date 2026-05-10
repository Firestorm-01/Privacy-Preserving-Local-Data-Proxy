"""Validation functions for structured identifiers with checksums."""
import re
from typing import Optional, Tuple


def luhn_checksum(card_number: str) -> bool:
    """
    Validate credit card number using Luhn algorithm.

    Args:
        card_number: Card number (digits only, spaces/dashes stripped)

    Returns:
        True if valid Luhn checksum
    """
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    # Luhn algorithm
    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit

    return checksum % 10 == 0


def validate_iban(iban: str) -> bool:
    """
    Validate IBAN using mod-97 algorithm.

    Args:
        iban: IBAN string (spaces allowed)

    Returns:
        True if valid IBAN checksum
    """
    iban = iban.replace(" ", "").upper()

    if len(iban) < 15 or len(iban) > 34:
        return False

    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]+$", iban):
        return False

    # Move first 4 chars to end
    rearranged = iban[4:] + iban[:4]

    # Convert letters to numbers (A=10, B=11, etc.)
    numeric = ""
    for char in rearranged:
        if char.isdigit():
            numeric += char
        else:
            numeric += str(ord(char) - ord("A") + 10)

    return int(numeric) % 97 == 1


def validate_ssn(ssn: str) -> bool:
    """
    Validate US Social Security Number format.

    Args:
        ssn: SSN string (with or without dashes)

    Returns:
        True if valid SSN format (not a known invalid pattern)
    """
    ssn = ssn.replace("-", "").replace(" ", "")

    if len(ssn) != 9 or not ssn.isdigit():
        return False

    area = int(ssn[:3])
    group = int(ssn[3:5])
    serial = int(ssn[5:])

    # Invalid patterns per SSA rules
    if area == 0 or area == 666 or area >= 900:
        return False
    if group == 0:
        return False
    if serial == 0:
        return False

    # Known advertising/example SSNs
    invalid_ssns = {
        "078051120",  # Woolworth wallet SSN
        "219099999",  # Used in ads
        "457555462",  # Lifelock CEO's SSN (widely publicized)
    }
    if ssn in invalid_ssns:
        return False

    return True


def validate_npi(npi: str) -> bool:
    """
    Validate National Provider Identifier using Luhn algorithm.

    Args:
        npi: 10-digit NPI string

    Returns:
        True if valid NPI checksum
    """
    npi = npi.replace(" ", "").replace("-", "")

    if len(npi) != 10 or not npi.isdigit():
        return False

    # NPI uses Luhn with prefix "80840"
    prefixed = "80840" + npi
    return luhn_checksum(prefixed)


def validate_credit_card_prefix(card_number: str) -> Optional[str]:
    """
    Identify card network by prefix (IIN/BIN).

    Args:
        card_number: Card number (digits only)

    Returns:
        Card network name or None if unrecognized
    """
    digits = "".join(c for c in card_number if c.isdigit())

    if not digits:
        return None

    # Visa
    if digits[0] == "4":
        return "visa"

    # Mastercard
    if len(digits) >= 2:
        prefix2 = int(digits[:2])
        if 51 <= prefix2 <= 55:
            return "mastercard"
        if len(digits) >= 4:
            prefix4 = int(digits[:4])
            if 2221 <= prefix4 <= 2720:
                return "mastercard"

    # American Express
    if len(digits) >= 2 and digits[:2] in ("34", "37"):
        return "amex"

    # Discover
    if len(digits) >= 4:
        if digits[:4] == "6011" or digits[:2] == "65":
            return "discover"
        if len(digits) >= 6:
            prefix6 = int(digits[:6])
            if 622126 <= prefix6 <= 622925:
                return "discover"

    return None


class ChecksumValidator:
    """Validates detected entities using checksums and format rules."""

    @staticmethod
    def validate(text: str, entity_type: str) -> Tuple[bool, float]:
        """
        Validate an entity and return confidence adjustment.

        Args:
            text: The detected text
            entity_type: Type of entity

        Returns:
            Tuple of (is_valid, confidence_multiplier)
        """
        clean = text.replace(" ", "").replace("-", "")

        if entity_type == "CREDIT_CARD":
            if luhn_checksum(clean):
                network = validate_credit_card_prefix(clean)
                if network:
                    return True, 1.0
                return True, 0.9
            return False, 0.3

        if entity_type == "IBAN":
            if validate_iban(text):
                return True, 1.0
            return False, 0.2

        if entity_type == "SSN":
            if validate_ssn(text):
                return True, 1.0
            return False, 0.3

        if entity_type == "NPI":
            if validate_npi(text):
                return True, 1.0
            return False, 0.2

        # No validation available - neutral
        return True, 1.0
