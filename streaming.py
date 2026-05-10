"""SSE streaming support with token-buffered unmasking."""
import asyncio
import json
import re
from typing import AsyncIterator
from dataclasses import dataclass, field

from vault import TokenVault


@dataclass
class StreamBuffer:
    """
    Buffers SSE chunks and unmasks tokens as complete tokens appear.

    Handles the challenge of tokens potentially being split across
    multiple SSE data events.
    """
    vault: TokenVault
    _buffer: str = field(default="")
    _token_pattern: re.Pattern = field(
        default_factory=lambda: re.compile(r"<[A-Z_]+_\d+>")
    )

    def process_chunk(self, chunk: str) -> str:
        """
        Process an SSE chunk, unmasking complete tokens.

        Args:
            chunk: Raw SSE data chunk

        Returns:
            Processed chunk with complete tokens unmasked
        """
        self._buffer += chunk

        # Find the last complete token or safe break point
        # We need to be careful not to unmask partial tokens

        # Check if buffer ends mid-token
        last_open = self._buffer.rfind("<")
        last_close = self._buffer.rfind(">")

        if last_open > last_close:
            # We might be mid-token, hold back everything after last_open
            safe_part = self._buffer[:last_open]
            self._buffer = self._buffer[last_open:]
        else:
            # No partial token, process everything
            safe_part = self._buffer
            self._buffer = ""

        # Unmask complete tokens in safe part
        return self.vault.unmask(safe_part)

    def flush(self) -> str:
        """
        Flush any remaining buffer content.
        Called at end of stream.
        """
        result = self.vault.unmask(self._buffer)
        self._buffer = ""
        return result


async def process_sse_stream(
    response_stream: AsyncIterator[bytes],
    vault: TokenVault,
) -> AsyncIterator[bytes]:
    """
    Process an SSE stream, unmasking tokens in the content.

    Handles OpenAI-style SSE format:
    data: {"choices": [{"delta": {"content": "..."}}]}

    Args:
        response_stream: Raw SSE byte stream from upstream
        vault: Token vault for this request

    Yields:
        Processed SSE bytes with tokens unmasked
    """
    buffer = StreamBuffer(vault=vault)

    async for chunk in response_stream:
        text = chunk.decode("utf-8")

        # Process each SSE event
        for line in text.split("\n"):
            if not line.startswith("data: "):
                yield (line + "\n").encode()
                continue

            data = line[6:]  # Remove "data: " prefix

            if data.strip() == "[DONE]":
                # Flush buffer and pass through
                remaining = buffer.flush()
                if remaining:
                    # Emit any remaining content
                    yield f"data: {json.dumps({'choices': [{'delta': {'content': remaining}}]})}\n".encode()
                yield (line + "\n").encode()
                continue

            try:
                payload = json.loads(data)

                # Handle OpenAI chat completion format
                if "choices" in payload and payload["choices"]:
                    for choice in payload["choices"]:
                        if "delta" in choice and "content" in choice["delta"]:
                            content = choice["delta"]["content"]
                            unmasked = buffer.process_chunk(content)
                            choice["delta"]["content"] = unmasked

                yield f"data: {json.dumps(payload)}\n".encode()

            except json.JSONDecodeError:
                # Pass through non-JSON data
                yield (line + "\n").encode()

    # Final flush
    remaining = buffer.flush()
    if remaining:
        yield f"data: {json.dumps({'choices': [{'delta': {'content': remaining}}]})}\n".encode()
