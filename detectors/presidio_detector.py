from typing import List, Optional
from .base import Detector, Detection

# Presidio imports with graceful fallback
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


class PresidioDetector(Detector):
    """Microsoft Presidio-based PII detection."""

    # Map Presidio entity types to our types
    ENTITY_MAP = {
        "PERSON": "PERSON",
        "EMAIL_ADDRESS": "EMAIL",
        "PHONE_NUMBER": "PHONE",
        "CREDIT_CARD": "CREDIT_CARD",
        "IBAN_CODE": "IBAN",
        "US_SSN": "SSN",
        "US_PASSPORT": "PASSPORT",
        "US_DRIVER_LICENSE": "DRIVERS_LICENSE",
        "IP_ADDRESS": "IP_ADDRESS",
        "MEDICAL_LICENSE": "MEDICAL_RECORD",
        "US_BANK_NUMBER": "BANK_ACCOUNT",
        "LOCATION": "LOCATION",
        "NRP": "ORG",  # Nationality, religious, political
        "DATE_TIME": "DATE",
        "ORGANIZATION": "ORG",
        "URL": "URL",
        "CRYPTO": "CRYPTO_WALLET",
        "UK_NHS": "MEDICAL_RECORD",
        "SG_NRIC_FIN": "SSN",  # Singapore national ID
        "AU_ABN": "ORG",  # Australian Business Number
        "AU_ACN": "ORG",  # Australian Company Number
    }

    def __init__(self):
        self._analyzer: Optional["AnalyzerEngine"] = None
        if PRESIDIO_AVAILABLE:
            self._initialize_analyzer()

    def _initialize_analyzer(self):
        """Initialize Presidio analyzer with all available recognizers."""
        try:
            # Configure NLP engine
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
            }

            try:
                provider = NlpEngineProvider(nlp_configuration=configuration)
                nlp_engine = provider.create_engine()
            except Exception:
                # Fallback without custom NLP config
                nlp_engine = None

            # Create analyzer with default recognizers
            self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine)

        except Exception as e:
            print(f"Warning: Could not initialize Presidio: {e}")
            self._analyzer = None

    @property
    def name(self) -> str:
        return "presidio"

    @property
    def available(self) -> bool:
        return self._analyzer is not None

    def detect(self, text: str) -> List[Detection]:
        if not self.available:
            return []

        detections = []

        try:
            results = self._analyzer.analyze(
                text=text,
                language="en",
                return_decision_process=True,
            )

            for result in results:
                entity_type = self.ENTITY_MAP.get(result.entity_type, result.entity_type)

                detected_text = text[result.start:result.end]

                # Skip masked tokens
                if detected_text.startswith("<") and detected_text.endswith(">"):
                    continue

                detection = Detection(
                    text=detected_text,
                    entity_type=entity_type,
                    start=result.start,
                    end=result.end,
                    confidence=result.score,
                    source=self.name,
                    metadata={
                        "presidio_entity": result.entity_type,
                        "recognizer": result.recognition_metadata.get("recognizer_name") if result.recognition_metadata else None,
                    }
                )
                detections.append(detection)

        except Exception as e:
            print(f"Presidio detection error: {e}")

        return detections
