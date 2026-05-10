import os
import json
import time
import secrets
from typing import Optional
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, HTTPException, Response, Depends
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from masker import get_masker
from vault import TokenVault
from streaming import process_sse_stream
from audit import get_audit_log, AuditEntry
from config.settings import settings


# ---------------------------------------------------------------------------
# Audit endpoint authentication
# ---------------------------------------------------------------------------
_audit_key_header = APIKeyHeader(name="X-Audit-Key", auto_error=False)


async def require_audit_auth(key: Optional[str] = Depends(_audit_key_header)) -> None:
    """
    Protects /audit/* routes. If PROXY_AUDIT_API_KEY is set, callers must
    supply it in the X-Audit-Key header. If the setting is empty (default),
    auth is skipped — fine for local dev, not for production.
    """
    configured = settings.audit_api_key
    if not configured:
        return  # No key configured — open access (dev mode)
    if not key or not secrets.compare_digest(key, configured):
        raise HTTPException(status_code=403, detail="Invalid or missing X-Audit-Key header")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    # Startup
    app.state.http = httpx.AsyncClient(timeout=120.0)

    # Initialize audit log
    audit = get_audit_log()
    await audit.initialize()

    # Pre-warm the masker (loads models)
    _ = get_masker()

    yield

    # Shutdown
    await app.state.http.aclose()


app = FastAPI(
    title="Privacy-Preserving Local Proxy",
    description="World-class PII detection and masking proxy",
    version="2.0.0",
    lifespan=lifespan,
)


# Request/Response Models
class InspectRequest(BaseModel):
    text: str


class InspectResponse(BaseModel):
    original: str
    masked: str
    detections: list
    entity_count: int
    entity_types: dict


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the inspector UI."""
    html_path = os.path.join(os.path.dirname(__file__), "client.html")
    try:
        with open(html_path) as f:
            return f.read()
    except FileNotFoundError:
        return HTMLResponse(
            content="<h1>Privacy Proxy</h1><p>Inspector UI not found. Use /docs for API.</p>",
            status_code=200
        )


@app.post("/inspect", response_model=InspectResponse)
async def inspect(request: InspectRequest):
    """
    Dry-run endpoint: shows what would be masked, without forwarding.
    Useful for testing and debugging detection rules.
    """
    masker = get_masker()
    vault = TokenVault()

    # Get detections for detailed view
    detections = masker.detect_all(request.text)

    # Perform masking
    masked = masker.mask_text(request.text, vault)

    return InspectResponse(
        original=request.text,
        masked=masked,
        detections=[
            {
                "text": d.text,
                "type": d.entity_type,
                "start": d.start,
                "end": d.end,
                "confidence": round(d.confidence, 3),
                "source": d.source,
            }
            for d in detections
        ],
        entity_count=vault.entity_count,
        entity_types=vault.entity_types,
    )


@app.get("/health")
async def health():
    """Health check endpoint."""
    masker = get_masker()
    return {
        "status": "healthy",
        "detectors": {
            "regex": True,
            "ner": masker.ner_detector.available,
            "presidio": masker.presidio_detector.available if masker.presidio_detector else False,
            "heuristic": True,
        },
        "settings": {
            "min_confidence": settings.min_confidence,
            "streaming_enabled": settings.enable_streaming,
            "audit_enabled": settings.enable_audit_log,
        }
    }


@app.get("/audit/stats")
async def audit_stats(
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    _: None = Depends(require_audit_auth),
):
    """Get audit statistics."""
    audit = get_audit_log()
    return await audit.get_stats(start_time, end_time)


@app.get("/audit/log")
async def audit_log_query(
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    session_id: Optional[str] = None,
    limit: int = 100,
    _: None = Depends(require_audit_auth),
):
    """Query audit log entries."""
    audit = get_audit_log()
    return await audit.query(start_time, end_time, session_id, limit)


@app.api_route("/proxy/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(path: str, request: Request):
    """
    Generic proxy endpoint: masks outgoing JSON, forwards to upstream,
    unmasks response so client sees coherent output.

    Supports both regular and streaming (SSE) responses.
    """
    start_time = time.time()
    vault = TokenVault()
    masker = get_masker()
    audit = get_audit_log()

    # Build outgoing headers
    skip_headers = {"host", "content-length", "authorization", "connection"}
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in skip_headers
    }

    # Add upstream auth if configured
    if settings.upstream_auth:
        headers["Authorization"] = settings.upstream_auth

    # Read and mask request body
    body_bytes = await request.body()
    masked_body = body_bytes

    if body_bytes:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            try:
                payload = json.loads(body_bytes)
                masked_payload = masker.mask_json(payload, vault)
                masked_body = json.dumps(masked_payload).encode()
            except json.JSONDecodeError as e:
                raise HTTPException(400, f"Invalid JSON body: {e}")

    # Build upstream URL
    upstream_url = f"{settings.upstream_base.rstrip('/')}/{path}"
    if request.url.query:
        upstream_url += f"?{request.url.query}"

    client: httpx.AsyncClient = request.app.state.http

    # Check if client wants streaming
    wants_streaming = (
        settings.enable_streaming and
        request.headers.get("accept", "").find("text/event-stream") >= 0
    )

    try:
        if wants_streaming:
            # Streaming response
            upstream_request = client.build_request(
                request.method,
                upstream_url,
                content=masked_body,
                headers=headers,
            )
            upstream = await client.send(upstream_request, stream=True)

            async def stream_generator():
                async for chunk in process_sse_stream(upstream.aiter_bytes(), vault):
                    yield chunk
                await upstream.aclose()

            # Log audit entry (entity count known from request masking)
            processing_time = (time.time() - start_time) * 1000
            await audit.log(AuditEntry(
                timestamp=start_time,
                session_id=vault.session_id,
                request_path=path,
                entity_count=vault.entity_count,
                entity_types=vault.entity_types,
                tokens=vault.get_audit_summary()["tokens"],
                response_status=upstream.status_code,
                processing_time_ms=processing_time,
            ))

            return StreamingResponse(
                stream_generator(),
                status_code=upstream.status_code,
                media_type="text/event-stream",
                headers={
                    "X-Masked-Entities": str(vault.entity_count),
                    "X-Session-Id": vault.session_id,
                },
            )

        else:
            # Regular response
            upstream = await client.request(
                request.method,
                upstream_url,
                content=masked_body,
                headers=headers,
            )

    except httpx.RequestError as e:
        raise HTTPException(502, f"Upstream connection error: {e}")

    # Process response
    content_type = upstream.headers.get("content-type", "")

    if content_type.startswith("application/json"):
        try:
            data = upstream.json()
            unmasked_data = masker.unmask_json(data, vault)

            # Log audit entry
            processing_time = (time.time() - start_time) * 1000
            await audit.log(AuditEntry(
                timestamp=start_time,
                session_id=vault.session_id,
                request_path=path,
                entity_count=vault.entity_count,
                entity_types=vault.entity_types,
                tokens=vault.get_audit_summary()["tokens"],
                response_status=upstream.status_code,
                processing_time_ms=processing_time,
            ))

            return JSONResponse(
                content=unmasked_data,
                status_code=upstream.status_code,
                headers={
                    "X-Masked-Entities": str(vault.entity_count),
                    "X-Session-Id": vault.session_id,
                },
            )
        except json.JSONDecodeError:
            pass

    # Fallback: text unmasking
    text = upstream.text
    unmasked_text = vault.unmask(text)

    processing_time = (time.time() - start_time) * 1000
    await audit.log(AuditEntry(
        timestamp=start_time,
        session_id=vault.session_id,
        request_path=path,
        entity_count=vault.entity_count,
        entity_types=vault.entity_types,
        tokens=vault.get_audit_summary()["tokens"],
        response_status=upstream.status_code,
        processing_time_ms=processing_time,
    ))

    return Response(
        content=unmasked_text,
        status_code=upstream.status_code,
        media_type=content_type or "text/plain",
        headers={
            "X-Masked-Entities": str(vault.entity_count),
            "X-Session-Id": vault.session_id,
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
