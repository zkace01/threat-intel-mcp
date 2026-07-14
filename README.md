# threat-intel-mcp

An MCP server for threat intelligence lookups and enrichment, with STIX 2.1 normalization, MISP/YARA enrichment, and a real Cortex XSOAR integration built on top of it.

## Objective

This project provides a reusable building block for threat intel enrichment that can be consumed two ways:

1. **As an MCP tool** — any MCP-compatible AI client (Claude, an internal SOC copilot, etc.) can call it to look up an indicator (IP, hash, domain) and get back a normalized, STIX-compliant answer, instead of the model having to know how to call AbuseIPDB or MISP directly.
2. **As a Cortex XSOAR integration** — the same enrichment logic is exposed as a proper XSOAR integration (built with `demisto-sdk`), so it can run inside a playbook as an automated step, not just be talked to by a chat agent.

The point of building it this way is that the enrichment logic is written once and consumed from both an AI-agent context and a classic SOAR-automation context — which is the actual shape of the "AI + SOAR" problem a Security Automation Engineer role deals with, not two disconnected demos.

Secondary goal: this is a portfolio project. It's built to be read by someone evaluating hands-on skill in MCP server development, threat intel data modeling (STIX), and SOAR integration development — not a production system.

## Architecture

```
        ┌──────────────────┐              ┌───────────────────┐
        │   MCP Client      │              │  Cortex XSOAR      │
        │ (Claude / agent)  │              │  Playbook           │
        └────────┬─────────┘              └─────────┬───────────┘
                 │ MCP protocol                     │ calls integration
                 │                                   │ (demisto-sdk)
        ┌────────▼───────────────────────────────────▼───────────┐
        │                    Enrichment Core                       │
        │        (shared Python package, no protocol-specific code)│
        │                                                            │
        │   - lookup_indicator(value, type) -> NormalizedResult      │
        │   - enrich(indicator) -> EnrichedResult                    │
        └────────────────────────┬─────────────────────────────────┘
                                 │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                            │
┌───────▼──────┐    ┌────────────▼────────┐    ┌──────────────▼──────┐
│  AbuseIPDB    │    │      MISP             │    │  YARA engine          │
│  client       │    │  (local, Docker)       │    │  (sample/IOC           │
│  (httpx)      │    │  (pymisp)              │    │  enrichment)           │
└───────┬──────┘    └────────────┬────────┘    └──────────────┬──────┘
        │                         │                            │
        └─────────────────────────┼─────────────────────────┘
                                 │
                        ┌────────▼─────────┐
                        │  STIX 2.1          │
                        │  normalization      │
                        │  (stix2)            │
                        └────────┬─────────┘
                                 │
                        ┌────────▼─────────┐
                        │  Storage backend   │
                        │  (abstract;         │
                        │   in-memory by      │
                        │   default, pluggable│
                        │   SQLite/Postgres)  │
                        └───────────────────┘
```

**Design decisions worth calling out:**

- **Enrichment core is protocol-agnostic.** The MCP server and the XSOAR integration are both thin adapters over the same core package — neither the MCP tool definitions nor the demisto-sdk integration script contain business logic. This is what makes "usable from an AI agent AND from a SOAR playbook" true rather than two separate implementations that drift apart.
- **XSOAR integration is real, not simulated.** Built with the official `demisto-sdk` (`demisto-sdk init --integration`), producing an actual installable integration (YAML spec + Python script), not a mocked call.
- **No user management.** This isn't a multi-user system. The MCP server has simple API-key authentication to protect the endpoint — that's authentication, not user management, and it's the only access-control concern in scope.
- **Storage is abstracted, not implemented up front.** A `StorageBackend` interface (`save_lookup()` / `get_cached()`) exists from the start, with an in-memory default. This keeps the MVP stateless while making it trivial to plug in SQLite or Postgres later (e.g., for caching lookups or keeping enrichment history) without touching the core logic.

**Components:**
- `core/` — protocol-agnostic enrichment logic (`lookup_indicator`, `enrich`), shared by both adapters
- `clients/` — clients for external sources (AbuseIPDB, MISP, YARA)
- `normalization/` — conversion of each source's response into STIX objects (Indicator, Observable)
- `storage/` — abstract storage backend + in-memory implementation
- `models/` — Pydantic schemas for requests/responses
- `mcp_server/` — MCP adapter (exposes tools: `check_ip`, `enrich_indicator`, `query_misp`)
- `xsoar/` — Cortex XSOAR integration (built with `demisto-sdk`) that calls into `core/`
- `tests/`

## Stack

- Python 3.12
- `httpx` — cliente HTTP
- `pydantic` — validación de esquemas
- `stix2` — normalización a STIX 2.1
- `pymisp` — cliente MISP
- `yara-python` — matching de reglas
- MCP SDK oficial (Python) para el server
- MISP en Docker (instancia local, solo para desarrollo/demo)
- Cortex XSOAR Community Edition (para probar la integración del playbook)

## Installation

```bash
git clone <repo>
cd threat-intel-mcp
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# copy and fill in environment variables
cp .env.example .env
# ABUSEIPDB_API_KEY=
# MISP_URL=
# MISP_API_KEY=
# MCP_SERVER_API_KEY=

# start local MISP (optional, only needed to test the MISP integration)
docker compose up -d misp

# run the MCP server
python -m mcp_server.main

# scaffold / run the XSOAR integration (requires demisto-sdk)
pip install demisto-sdk
demisto-sdk init --integration -o xsoar/
```

## Project roadmap

1. **MVP:** MCP server with a single tool (`check_ip`) against AbuseIPDB, no STIX yet — validate that the MCP protocol and the basic flow work end to end before adding modeling complexity.
2. STIX 2.1 normalization of AbuseIPDB responses, and refactor of the enrichment logic into the protocol-agnostic `core/` package.
3. Local MISP integration (Docker) as a second source, reusing the STIX normalization layer.
4. Enrichment with `yara-python` over samples/IOCs.
5. Real Cortex XSOAR integration (via `demisto-sdk`) that calls into `core/`, wired into a sample playbook.
6. Final documentation: architecture diagram, README, design decisions.

## Status

Work in progress — portfolio project, not intended for production use.

## Open decisions / up for debate

- **MVP-before-STIX ordering:** I'd validate the MCP server against raw AbuseIPDB JSON before adding STIX, rather than normalizing from day one. Reasoning: STIX adds modeling complexity; if the basic MCP protocol flow needs rework, better to find out before investing in normalization. If you'd rather start with STIX from the start to avoid rewriting later, say so and we'll change the order.
- **Local MISP in Docker:** adds non-trivial infrastructure (stand up, maintain, seed with data) just for a demo. Lighter alternative: mock MISP responses with fixtures and leave the real integration "documented but not deployed." Depends on how much time you want to spend on that piece versus the rest.
- **`core/` as a shared package from the start:** I'm proposing the MCP server and the XSOAR integration both sit on top of a shared, protocol-agnostic `core/` package rather than each implementing its own enrichment logic. This is more setup up front (an extra abstraction layer) but avoids the two adapters drifting apart later. If the timeline is tight, an alternative is to build the MCP server first, get it working end to end, and only extract `core/` when the XSOAR integration starts (step 5) — less upfront design, some refactoring risk later. Your call.
