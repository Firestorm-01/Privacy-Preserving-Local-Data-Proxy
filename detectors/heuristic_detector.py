import re
from typing import List, Set
from .base import Detector, Detection


class HeuristicDetector(Detector):
    """
    Context-aware heuristic detection for edge cases that
    statistical NER and regex miss or misclassify.
    """

    # Words that indicate a person's name follows
    PERSON_INDICATORS = {
        "my name is", "i am", "i'm", "this is", "call me",
        "contact", "authored by", "created by", "written by",
        "from:", "to:", "dear", "hi ", "hello ", "hey ",
        "signed", "regards", "sincerely", "best,", "thanks,",
    }

    # Words that reduce likelihood of PERSON (product names, etc.)
    PERSON_REDUCERS = {
        "library", "package", "framework", "app", "application",
        "software", "product", "service", "platform", "tool",
        "version", "release", "update", "v1", "v2", "beta",
    }

    # Domains that are clearly not real email addresses
    FAKE_EMAIL_DOMAINS = {
        "example.com", "example.org", "example.net",
        "test.com", "test.org", "localhost",
        "foo.com", "bar.com", "invalid",
    }

    # Common placeholder names
    PLACEHOLDER_NAMES = {
        "john doe", "jane doe", "john smith", "jane smith",
        "test user", "admin", "administrator", "root",
        "foo bar", "alice", "bob", "charlie",  # Crypto examples
    }

    @property
    def name(self) -> str:
        return "heuristic"

    def detect(self, text: str) -> List[Detection]:
        detections = []
        text_lower = text.lower()

        # Detect names after indicators
        detections.extend(self._detect_names_with_context(text, text_lower))

        # Detect inline credentials
        detections.extend(self._detect_inline_credentials(text))

        return detections

    def _detect_names_with_context(self, text: str, text_lower: str) -> List[Detection]:
        """Find names that appear after strong contextual indicators."""
        detections = []

        for indicator in self.PERSON_INDICATORS:
            idx = text_lower.find(indicator)
            if idx == -1:
                continue

            # Extract what follows the indicator
            start = idx + len(indicator)

            # Skip whitespace
            while start < len(text) and text[start] in " \t":
                start += 1

            if start >= len(text):
                continue

            # Find the end of the potential name (next punctuation or newline)
            end = start
            while end < len(text) and text[end] not in ".,!?;\n\r":
                end += 1

            potential_name = text[start:end].strip()

            # Basic length validation
            if len(potential_name) < 2 or len(potential_name) > 50:
                continue

            # Skip if it looks like a placeholder
            if potential_name.lower() in self.PLACEHOLDER_NAMES:
                continue

            # Skip if it's all caps (likely an acronym)
            if potential_name.isupper() and len(potential_name) > 3:
                continue

            # Require at least 2 words — single words are too noisy
            words = potential_name.split()
            if len(words) < 2:
                continue

            # Require all words to start with a capital letter (title-case name)
            # This filters out plain sentences that follow indicators like "Hi there"
            if not all(w[0].isupper() for w in words if w.isalpha()):
                continue

            # Check if nearby text contains reducers
            context_window = text_lower[max(0, idx - 50):min(len(text), end + 50)]
            confidence = 0.75
            for reducer in self.PERSON_REDUCERS:
                if reducer in context_window:
                    confidence -= 0.1

            if confidence >= 0.5:
                detections.append(Detection(
                    text=potential_name,
                    entity_type="PERSON",
                    start=start,
                    end=end,
                    confidence=confidence,
                    source=self.name,
                    metadata={"indicator": indicator}
                ))

        return detections

    def _detect_inline_credentials(self, text: str) -> List[Detection]:
        """Detect credentials in assignment patterns that regex might miss."""
        detections = []

        # Patterns like: password = "...", secret: '...'
        credential_pattern = re.compile(
            r"""
            (?:password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?key|access[_-]?key)
            \s*[=:]\s*
            (?:
                ["']([^"']{4,100})["']  # Quoted value
                |
                (\S{8,100})  # Unquoted value
            )
            """,
            re.IGNORECASE | re.VERBOSE
        )

        for match in credential_pattern.finditer(text):
            value = match.group(1) or match.group(2)
            if value:
                # Determine start/end of the actual credential
                if match.group(1):
                    start = match.start(1)
                    end = match.end(1)
                else:
                    start = match.start(2)
                    end = match.end(2)

                detections.append(Detection(
                    text=value,
                    entity_type="SECRET",
                    start=start,
                    end=end,
                    confidence=0.90,
                    source=self.name,
                    metadata={"pattern": "credential_assignment"}
                ))

        return detections

    def adjust_confidence(self, detection: Detection, text: str) -> float:
        """
        Adjust confidence based on surrounding context.
        Called by the masker to refine other detectors' results.
        """
        text_lower = text.lower()
        confidence = detection.confidence

        # Context window around the detection
        window_start = max(0, detection.start - 50)
        window_end = min(len(text), detection.end + 50)
        context = text_lower[window_start:window_end]

        if detection.entity_type == "PERSON":
            # Boost for strong person indicators
            for indicator in self.PERSON_INDICATORS:
                if indicator in context:
                    confidence = min(1.0, confidence + 0.1)
                    break

            # Reduce for product/code context
            for reducer in self.PERSON_REDUCERS:
                if reducer in context:
                    confidence = max(0.0, confidence - 0.15)

        elif detection.entity_type == "EMAIL":
            # Reduce confidence for fake/example domains
            email_lower = detection.text.lower()
            for fake_domain in self.FAKE_EMAIL_DOMAINS:
                if email_lower.endswith("@" + fake_domain):
                    confidence = max(0.0, confidence - 0.5)
                    break

        elif detection.entity_type == "ORG":
            # Reduce confidence for common false positives
            org_lower = detection.text.lower()
            if org_lower in {"the", "a", "an", "this", "that"}:
                confidence = 0.0
            elif len(detection.text) < 3:
                confidence = max(0.0, confidence - 0.3)

        return confidence
