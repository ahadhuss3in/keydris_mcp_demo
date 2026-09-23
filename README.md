# Governed SecOps Agent (PoC)

An agent that autonomously investigates security alerts but cannot take a
containment action until **typed, mathematical guardrails** authorize it.

```
                 System 2 (reasoning)          System 1 (decision)        Execution gate
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Security    │──▶│ Investigator │──▶│    Judge     │──▶│     Enforcer     │──▶│ Keydris-guarded  │
│  alert/logs  │   │  LLM (S2)    │   │  Jev Choice  │   │  MCP client call │   │  MCP block_ip    │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────────┘   └──────────────────┘
                        LangGraph state machine                 governance ctx        PolicyEngine
```

## Stack

| Layer | Tech | Role |
|---|---|---|
| Orchestration | **LangGraph** | Stateful workflow + conditional edges |
| Investigator | **DeepSeek V4.1 Flash** via OpenRouter (`langchain-openai`) | Reads raw logs, writes a summary |
| Judge | **Jev / TypeSafe System One** (`typesafe/jev-1.13` via OpenRouter) | Typed `choice`: `benign \| suspicious \| malicious` + confidence |
| Authorization gateway | **Keydris** middleware (`governance/keydris.py`) | Deterministic policy engine that gates execution |
| Tool transport | **MCP** (`fastmcp` server, stdio client) | Exposes the `block_ip` containment tool |

Jev is a *System One* decision model: it does not generate text, it returns a
typed value with a probability distribution. That is what makes the hand-off
deterministic — the graph branches on a validated enum, never on prose.

## Project structure

```
keydris_demo_mcp/
├── agent_workflow.py         # LangGraph: investigate → judge → route → enforcer/approval/no_action
├── mcp_server.py             # FastMCP server exposing block_ip, wrapped by @keydris_guard
├── run_demo.py               # Runs the mock alerts end-to-end
├── governance/
│   ├── schemas.py            # Pydantic contracts (verdicts, governance ctx, tool responses)
│   ├── jev_client.py         # Jev Choice-primitive client (fail-closed)
│   ├── keydris.py            # keydris-reader + PolicyEngine + @keydris_guard middleware
│   └── config.py             # .env loading + defaults
├── clients/mcp_client.py     # stdio MCP client (+ in-process fallback)
├── data/alerts.json          # mock alerts: auto-block / approval / benign / boundary
└── tests/test_guardrails.py  # policy boundaries, intercept behavior, routing
```

## Setup

```bash
uv sync
cp .env.example .env          # then add your OPENROUTER_API_KEY
```

`.env` keys:

```
OPENROUTER_API_KEY=sk-or-...
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
LLM_MODEL_NAME=deepseek/deepseek-v4.1-flash
TYPESAFE_MODEL_NAME=typesafe/jev-1.13
```

The same OpenRouter key powers both the investigator LLM and Jev.

## Run

```bash
python run_demo.py
python run_demo.py --alert-id ALT-2026-0001
python run_demo.py --transport inprocess     # skip spawning the MCP subprocess
```

```bash
pytest
```

## Run with Docker

Everything (agent + Jev client + Keydris-guarded MCP server + tests) is packaged
in one image. The stdio MCP server is spawned as a child process inside the
container, so no extra service is needed.

```bash
# Build
docker build -t governed-secops-agent .

# Run the full demo (secrets read from your host .env at runtime, never baked in)
docker run --rm --env-file .env governed-secops-agent

# Run one alert
docker run --rm --env-file .env governed-secops-agent \
  python run_demo.py --alert-id ALT-2026-0001

# Run the offline guardrail tests (no API key required)
docker run --rm governed-secops-agent python -m pytest

# Force the in-process MCP transport instead of spawning the server
docker run --rm --env-file .env -e ENFORCER_TRANSPORT=inprocess governed-secops-agent
```

`.env` is excluded from the image via `.dockerignore`; `--env-file` injects the
values only at runtime.

## The authorization rule (Keydris `PolicyEngine`)

| Jev verdict | Confidence | Decision | Tool body runs? |
|---|---|---|---|
| `malicious` | `> 0.90` | `ALLOWED` | ✅ yes — auto-block |
| `malicious` | `<= 0.90` (incl. exactly 0.90) | `APPROVAL_REQUIRED` | ❌ intercepted |
| `suspicious` | any | `APPROVAL_REQUIRED` | ❌ intercepted |
| `benign` | `>= 0.90` | `NO_ACTION` | ❌ no containment needed |
| `benign` | `< 0.90` | `APPROVAL_REQUIRED` | ❌ fail closed |
| missing/malformed context | — | `DENIED` | ❌ fail closed |

The `0.90` boundary is treated as *not proven malicious* (fail-closed), and the
threshold is tunable via `KEYDRIS_AUTO_BLOCK_MIN_CONFIDENCE`.

> **Note on Jev confidence:** Jev's `confidence` describes how concentrated the
> verdict distribution is, not a calibrated probability that an action is safe.
> The PoC also persists `probabilities["malicious"]` in graph state so the gate
> can be tuned to use it later. Pick thresholds from the cost of each mistake.

## Hand-off semantics

1. **LangGraph → Jev:** the investigator's *summary* (plus raw logs) is flattened
   into Jev's `state`; Jev returns a typed `choice` + `confidence`.
2. **LangGraph → MCP:** the `enforcer` node sends `block_ip(ip, reason, governance)`
   where `governance` is the serialized `GovernanceContext` (the agent's *claim*).
3. **Keydris → tool:** the keydris-reader lifts that claim into request context;
   `@keydris_guard` evaluates the policy engine and either runs the tool body or
   returns `APPROVAL_REQUIRED`. The graph never blocks on its own — Keydris is the
   sole execution authority.

## Fail-closed guarantee

Any Jev transport error, HTTP error, or schema violation yields
`verdict=suspicious, confidence=0.0, failed_closed=true`, which can never
auto-execute. A broken classifier cannot unlock containment.# keydris_mcp_demo
