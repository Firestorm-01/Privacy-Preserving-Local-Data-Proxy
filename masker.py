from typing import List, Optional, Any, Dict
import yaml
import re
import sys
import os
import hashlib
from pathlib import Path
from cachetools import TTLCache

# Ensure the project root is on sys.path when running directly
sys.path.insert(0, os.path.dirname(__file__))

from detectors import (
    Detection,
    RegexDetector,
    NERDetector,
    PresidioDetector,
    HeuristicDetector,
    ChecksumValidator,
)
from vault import TokenVault
from config.settings import settings


class EntityConfig:
    """Loads and manages custom entity configuration."""

    def __init__(self, config_path: str):
        self.deny_list: Dict[str, List[str]] = {}
        self.allow_list: set = set()
        self.custom_patterns: List[tuple] = []
        self.context_rules: Dict[str, dict] = {}

        self._load_config(config_path)

    def _load_config(self, config_path: str):
        path = Path(config_path)
        if not path.exists():
            return

        try:
            with open(path) as f:
                config = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: Could not load entity config: {e}")
            return

        # Parse deny list
        for item in config.get("deny_list", []):
            entity_type = item.get("entity_type", "CUSTOM")
            patterns = item.get("patterns", [])
            self.deny_list[entity_type] = [p.lower() for p in patterns]

        # Parse allow list
        self.allow_list = {item.lower() for item in config.get("allow_list", [])}

        # Parse custom patterns
        for item in config.get("custom_patterns", []):
            try:
                pattern = re.compile(item["pattern"], re.IGNORECASE)
                self.custom_patterns.append((
                    item.get("entity_type", "CUSTOM"),
                    pattern,
                    item.get("confidence", 0.8),
                ))
            except re.error as e:
                print(f"Invalid regex pattern: {item.get('pattern')}: {e}")

        # Parse context rules
        for item in config.get("context_rules", []):
            entity_type = item.get("entity_type")
            if entity_type:
                self.context_rules[entity_type] = {
                    "boost": [c.lower() for c in item.get("boost_contexts", [])],
                    "reduce": [c.lower() for c in item.get("reduce_contexts", [])],
                }

    def is_allowed(self, text: str) -> bool:
        """Check if text is in the allow list (should not be masked)."""
        return text.lower() in self.allow_list

    def check_deny_list(self, text: str) -> Optional[str]:
        """Check if text matches deny list, return entity type if so."""
        text_lower = text.lower()
        for entity_type, patterns in self.deny_list.items():
            if text_lower in patterns:
                return entity_type
        return None

    def get_custom_detections(self, text: str) -> List[Detection]:
        """Run custom pattern matching."""
        detections = []
        for entity_type, pattern, confidence in self.custom_patterns:
            for match in pattern.finditer(text):
                detections.append(Detection(
                    text=match.group(0),
                    entity_type=entity_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    source="custom_config",
                ))
        return detections


# Module-level singleton for entity config — not lru_cache, so reload() works
_entity_config: Optional["EntityConfig"] = None


def get_entity_config(reload: bool = False) -> "EntityConfig":
    global _entity_config
    if _entity_config is None or reload:
        _entity_config = EntityConfig(settings.entities_config_path)
    return _entity_config


class Masker:
    """
    Orchestrates multi-engine PII detection and masking.
    """

    def __init__(self):
        self.regex_detector = RegexDetector()
        self.ner_detector = NERDetector()
        self.heuristic_detector = HeuristicDetector()

        self.presidio_detector = None
        if settings.enable_presidio:
            self.presidio_detector = PresidioDetector()

        self.validator = ChecksumValidator()
        self.entity_config = get_entity_config()

        # Cache for repeated text patterns
        self._detection_cache: TTLCache = TTLCache(
            maxsize=1000,
            ttl=settings.cache_ttl_seconds
        )

    def detect_all(self, text: str) -> List[Detection]:
        """
        Run all detection engines and merge results.

        Returns deduplicated, validated detections sorted by position.
        """
        # Use full-text MD5 as cache key — avoids collisions from same-prefix texts
        cache_key = hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()
        if cache_key in self._detection_cache:
            return self._detection_cache[cache_key]

        all_detections: List[Detection] = []

        # 1. Custom config patterns (highest priority)
        all_detections.extend(self.entity_config.get_custom_detections(text))

        # 2. Regex detector (structured patterns)
        all_detections.extend(self.regex_detector.detect(text))

        # 3. spaCy NER (names, orgs, locations)
        all_detections.extend(self.ner_detector.detect(text))

        # 4. Presidio (if enabled)
        if self.presidio_detector and self.presidio_detector.available:
            all_detections.extend(self.presidio_detector.detect(text))

        # 5. Heuristic detector (context-based)
        all_detections.extend(self.heuristic_detector.detect(text))

        # Filter, validate, and deduplicate
        detections = self._process_detections(all_detections, text)

        # Cache the result
        self._detection_cache[cache_key] = detections

        return detections

    def _process_detections(self, detections: List[Detection], text: str) -> List[Detection]:
        """Filter, validate, deduplicate, and sort detections."""
        processed = []

        for det in detections:
            # Skip if in allow list
            if self.entity_config.is_allowed(det.text):
                continue

            # Skip if below minimum confidence
            if det.confidence < settings.min_confidence:
                continue

            # Apply checksum validation where applicable
            is_valid, confidence_mult = self.validator.validate(det.text, det.entity_type)
            if not is_valid and confidence_mult < 0.5:
                continue
            det.confidence *= confidence_mult

            # Apply context adjustments from heuristic detector
            det.confidence = self.heuristic_detector.adjust_confidence(det, text)

            # Re-check confidence after adjustments
            if det.confidence < settings.min_confidence:
                continue

            processed.append(det)

        # Deduplicate overlapping detections
        processed = self._deduplicate(processed)

        # Sort by position
        processed.sort(key=lambda d: (d.start, -d.end))

        return processed

    def _deduplicate(self, detections: List[Detection]) -> List[Detection]:
        """
        Remove overlapping detections, keeping the highest confidence one.
        For equal confidence, prefer longer matches.
        """
        if not detections:
            return []

        # Sort by confidence desc, then by length desc
        sorted_dets = sorted(
            detections,
            key=lambda d: (-d.confidence, -(d.end - d.start))
        )

        kept = []
        for det in sorted_dets:
            # Check if this detection overlaps with any we're keeping
            overlaps = False
            for existing in kept:
                if det.overlaps(existing):
                    overlaps = True
                    break

            if not overlaps:
                kept.append(det)

        return kept

    def mask_text(self, text: str, vault: TokenVault) -> str:
        """
        Detect and mask all PII in text.

        Args:
            text: Input text
            vault: Token vault for this request

        Returns:
            Text with PII replaced by tokens
        """
        detections = self.detect_all(text)

        if not detections:
            return text

        # Sort by start position descending to replace from end
        # This preserves earlier positions while replacing
        detections.sort(key=lambda d: d.start, reverse=True)

        result = text
        for det in detections:
            token = vault.mask(det.text, det.entity_type, det.confidence)
            result = result[:det.start] + token + result[det.end:]

        return result

    def mask_json(self, obj: Any, vault: TokenVault) -> Any:
        """Recursively mask PII in JSON-like structures."""
        if isinstance(obj, dict):
            return {k: self.mask_json(v, vault) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.mask_json(item, vault) for item in obj]
        if isinstance(obj, str):
            return self.mask_text(obj, vault)
        return obj

    def unmask_json(self, obj: Any, vault: TokenVault) -> Any:
        """Recursively unmask tokens in JSON-like structures."""
        if isinstance(obj, dict):
            return {k: self.unmask_json(v, vault) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.unmask_json(item, vault) for item in obj]
        if isinstance(obj, str):
            return vault.unmask(obj)
        return obj


# Singleton instance
_masker: Optional[Masker] = None


def get_masker() -> Masker:
    global _masker
    if _masker is None:
        _masker = Masker()
    return _masker
