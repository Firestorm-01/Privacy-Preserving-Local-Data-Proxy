from dataclasses import dataclass, field
from typing import Dict, Optional
import uuid
import time


@dataclass
class TokenVault:
    """
    Bidirectional mapping: original <-> masked token.
    Per-request, ephemeral, with optional TTL.
    """
    forward: Dict[str, str] = field(default_factory=dict)   # original -> token
    reverse: Dict[str, str] = field(default_factory=dict)   # token -> original
    counters: Dict[str, int] = field(default_factory=dict)  # entity_type -> next id
    metadata: Dict[str, dict] = field(default_factory=dict) # token -> metadata
    _session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    _created_at: float = field(default_factory=time.time)

    def mask(self, original: str, entity_type: str, confidence: float = 1.0) -> str:
        """
        Get or create a masked token for the original value.

        Args:
            original: The sensitive value to mask
            entity_type: Type of entity (PERSON, EMAIL, etc.)
            confidence: Detection confidence score

        Returns:
            Masked token like <PERSON_0>
        """
        if original in self.forward:
            return self.forward[original]

        idx = self.counters.get(entity_type, 0)
        self.counters[entity_type] = idx + 1

        token = f"<{entity_type}_{idx}>"

        self.forward[original] = token
        self.reverse[token] = original
        self.metadata[token] = {
            "entity_type": entity_type,
            "confidence": confidence,
            "index": idx,
            "length": len(original),
        }

        return token

    def unmask(self, text: str) -> str:
        """
        Replace every token in text with its original value.
        Sorts by length descending to avoid partial overlaps.
        """
        # Sort by length descending to prevent <PERSON_1> matching inside <PERSON_10>
        for token in sorted(self.reverse.keys(), key=len, reverse=True):
            text = text.replace(token, self.reverse[token])
        return text

    def unmask_token(self, token: str) -> Optional[str]:
        """Get the original value for a specific token."""
        return self.reverse.get(token)

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def entity_count(self) -> int:
        return len(self.forward)

    @property
    def entity_types(self) -> Dict[str, int]:
        """Count of each entity type masked."""
        return dict(self.counters)

    def get_audit_summary(self) -> dict:
        """
        Return audit-safe summary (no original values).
        """
        return {
            "session_id": self._session_id,
            "timestamp": self._created_at,
            "entity_count": self.entity_count,
            "entity_types": self.entity_types,
            "tokens": [
                {
                    "token": token,
                    "entity_type": meta["entity_type"],
                    "confidence": meta["confidence"],
                    "original_length": meta["length"],
                }
                for token, meta in self.metadata.items()
            ],
        }
