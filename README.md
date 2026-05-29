# Privacy-Preserving Local Data Proxy
⚠️Entire project needs to be tested before usage.This is a prototype.
A  local proxy that detects and masks PII before forwarding requests to upstream LLM APIs (OpenAI, etc.), then unmasks tokens in the response — so your application sees coherent output while sensitive data never leaves your network in the clear.

---

## Features

- **Multi-engine detection** — spaCy NER, regex patterns, Microsoft Presidio, and custom heuristics
- **Confidence scoring** — each detection carries a score; configurable threshold filters false positives
- **Context-aware masking** — surrounding text adjusts confidence (e.g. reduces false positives on product names)
- **40+ entity types** — personal, financial, medical, infrastructure, and international formats
- **Checksum validation** — Luhn (credit cards), IBAN mod-97, SSN, NPI
- **Streaming support** — handles SSE responses from OpenAI with token-safe buffering
- **Compliance audit log** — SQLite log of every masking event, no original values stored
- **Deny/allow lists** — per-project customization via `config/entities.yaml`
- **Inspector UI** — browser-based dry-run tool at `http://localhost:8000`

---

## Project Structure

```
privacy_proxy/
├── main.py                        # FastAPI app + routes
├── masker.py                      # Orchestrator for all detection engines
├── vault.py                       # Per-request token store
├── streaming.py                   # SSE response handling
├── audit.py                       # Compliance audit logging
├── client.html                    # Browser-based inspector UI
├── requirements.txt
├── config/
│   ├── settings.py                # Pydantic settings (env-configurable)
│   └── entities.yaml              # Custom entity rules
├── detectors/
│   ├── __init__.py
│   ├── base.py                    # Abstract detector interface + Detection dataclass
│   ├── regex_detector.py          # Pattern-based detection
│   ├── ner_detector.py            # spaCy NER
│   ├── presidio_detector.py       # Microsoft Presidio
│   ├── heuristic_detector.py      # Context-aware heuristics
│   └── checksum_validator.py      # Luhn, IBAN, SSN, NPI validation
└── tests/
    ├── __init__.py
    ├── test_detectors.py
    └── test_masker.py
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

> **Tip:** If `en_core_web_lg` is unavailable, the NER detector automatically falls back to `en_core_web_sm`.

### 2. Run in inspection mode (no upstream needed)

```bash
uvicorn main:app --reload --port 8000
```

Open [http://localhost:8000](http://localhost:8000) for the inspector UI, or [http://localhost:8000/docs](http://localhost:8000/docs) for the interactive API docs.

### 3. Run as a proxy in front of OpenAI

```bash
export PROXY_UPSTREAM_BASE="https://api.openai.com"
export PROXY_UPSTREAM_AUTH="Bearer sk-your-openai-key"
export PROXY_MIN_CONFIDENCE=0.7

uvicorn main:app --reload --port 8000
```

Point your application at `http://localhost:8000/proxy/v1/chat/completions` instead of `https://api.openai.com/v1/chat/completions`.

---

## Configuration

All settings are configurable via environment variables or a `.env` file.

| Variable | Default | Description |
|---|---|---|
| `PROXY_UPSTREAM_BASE` | `https://api.openai.com` | Upstream API base URL |
| `PROXY_UPSTREAM_AUTH` | _(empty)_ | `Authorization` header for upstream |
| `PROXY_MIN_CONFIDENCE` | `0.7` | Minimum detection confidence (0–1) |
| `PROXY_ENABLE_PRESIDIO` | `true` | Enable Microsoft Presidio detectors |
| `PROXY_ENABLE_AUDIT_LOG` | `true` | Enable SQLite audit logging |
| `PROXY_ENABLE_STREAMING` | `true` | Enable SSE streaming support |
| `PROXY_CACHE_TTL_SECONDS` | `300` | TTL for detection result cache |
| `PROXY_AUDIT_API_KEY` | _(empty)_ | API key for `/audit/*` endpoints (`X-Audit-Key` header). Empty = open (dev only) |
| `PROXY_AUDIT_DB_PATH` | `audit.db` | Path to SQLite audit database |

### .env example

```env
PROXY_UPSTREAM_BASE=https://api.openai.com
PROXY_UPSTREAM_AUTH=Bearer sk-your-key
PROXY_MIN_CONFIDENCE=0.75
PROXY_ENABLE_PRESIDIO=true
```

---

## Custom Entity Rules (`config/entities.yaml`)

### Deny list — always mask these strings

```yaml
deny_list:
  - entity_type: INTERNAL_PROJECT
    patterns:
      - "project-phoenix"
      - "codename-atlas"
```

### Allow list — never mask these strings

```yaml
allow_list:
  - "example.com"
  - "localhost"
  - "John Doe"   # common placeholder
```

### Custom regex patterns

```yaml
custom_patterns:
  - entity_type: EMPLOYEE_ID
    pattern: "EMP-\\d{6}"
    confidence: 0.95
```

### Context rules — boost or reduce confidence by surrounding text

```yaml
context_rules:
  - entity_type: PERSON
    boost_contexts:
      - "my name is"
      - "authored by"
    reduce_contexts:
      - "library"
      - "framework"
```

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/` | Inspector UI |
| `POST` | `/inspect` | Dry-run: detect and mask without forwarding |
| `GET` | `/health` | Health check + detector status |
| `ANY` | `/proxy/{path}` | Proxy to upstream with masking |
| `GET` | `/audit/stats` | Aggregate audit statistics |
| `GET` | `/audit/log` | Query audit log entries |

### `/inspect` example

```bash
curl -s -X POST http://localhost:8000/inspect \
  -H "Content-Type: application/json" \
  -d '{"text": "My email is alice@corp.com and my card is 4532015112830366"}' \
  | python3 -m json.tool
```

---

## Running Tests

```bash
# From the privacy_proxy directory
pytest tests/ -v
```

---

## Supported Entity Types

| Category | Types |
|---|---|
| Personal | PERSON, EMAIL, PHONE, SSN, PASSPORT, DRIVERS_LICENSE |
| Financial | CREDIT_CARD, IBAN, BANK_ACCOUNT, CRYPTO_WALLET |
| Infrastructure | API_KEY, JWT, PASSWORD, SECRET, IP_ADDRESS, MAC_ADDRESS, PATH, URL |
| Organizational | ORG, LOCATION |
| Medical | MEDICAL_RECORD, NPI |
| General | UUID, CUSTOM |

---

## How It Works

1. **Request arrives** at `/proxy/{path}`
2. **Masker scans** the JSON body using all four detection engines
3. **PII is replaced** with tokens like `<EMAIL_0>`, `<API_KEY_1>`
4. **Masked request** is forwarded to the upstream API
5. **Upstream response** is scanned for tokens and unmasked before returning to the caller
6. **Audit entry** is written to SQLite (no original values stored)

For streaming responses, the proxy buffers SSE chunks to ensure tokens are never split mid-stream before unmasking.

---

## Security Notes

- The vault is **per-request and in-memory** — tokens do not persist between requests
- The audit log records entity types, counts, and token lengths — **never original values**
- The allow list prevents false-positive masking of known safe values (test addresses, placeholders)
- Checksum validation (Luhn, IBAN mod-97) significantly reduces false positives on structured identifiers
