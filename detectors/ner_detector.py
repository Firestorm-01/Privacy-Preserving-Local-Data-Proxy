import spacy
from typing import List
from functools import lru_cache
from .base import Detector, Detection


@lru_cache(maxsize=1)
def load_spacy_model():
    """Load spaCy model once and cache it."""
    try:
        return spacy.load("en_core_web_lg")
    except OSError:
        # Fallback to smaller model if large isn't available
        try:
            return spacy.load("en_core_web_sm")
        except OSError:
            return None


class NERDetector(Detector):
    """Named Entity Recognition using spaCy."""

    # Map spaCy labels to our entity types
    ENTITY_MAP = {
        "PERSON": ("PERSON", 0.85),
        "ORG": ("ORG", 0.80),
        "GPE": ("LOCATION", 0.85),
        "LOC": ("LOCATION", 0.80),
        "FAC": ("LOCATION", 0.75),
        "MONEY": ("MONEY", 0.90),
        "DATE": ("DATE", 0.70),
        "TIME": ("TIME", 0.70),
        "NORP": ("ORG", 0.60),  # Nationalities, religious, political groups
    }

    def __init__(self):
        self._nlp = load_spacy_model()

    @property
    def name(self) -> str:
        return "spacy_ner"

    @property
    def available(self) -> bool:
        return self._nlp is not None

    def detect(self, text: str) -> List[Detection]:
        if not self.available:
            return []

        detections = []
        doc = self._nlp(text)

        for ent in doc.ents:
            if ent.label_ not in self.ENTITY_MAP:
                continue

            # Skip if already looks like a masked token
            if ent.text.startswith("<") and ent.text.endswith(">"):
                continue

            # Skip very short entities (likely false positives)
            if len(ent.text.strip()) < 2:
                continue

            entity_type, base_confidence = self.ENTITY_MAP[ent.label_]

            detection = Detection(
                text=ent.text,
                entity_type=entity_type,
                start=ent.start_char,
                end=ent.end_char,
                confidence=base_confidence,
                source=self.name,
                metadata={
                    "spacy_label": ent.label_,
                    "spacy_kb_id": ent.kb_id_ if ent.kb_id_ else None,
                }
            )
            detections.append(detection)

        return detections
