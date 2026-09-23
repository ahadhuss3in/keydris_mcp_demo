"""LangGraph workflow for the Governed SecOps Agent.

This is the "System 2" plane: a reasoning LLM investigates the alert, Jev
(``System 1``) collapses the prose into a typed verdict, and the Keydris-gated
MCP enforcer executes containment only when the policy engine authorizes it.

    START
      |
      v
  investigate   (LLM: GPT/Claude/DeepSeek reads raw logs -> summary)
      |
      v
    judge       (Jev Choice primitive: benign | suspicious | malicious + confidence)
      |
      v  route_after_judge
      +-----------------------------+
      |                             |
      v                             v
   enforcer                     no_action        (confidently benign)
   (MCP block_ip,                  |
    Keydris-gated)                 v
      |                          END
      v  route_after_enforcer
      +----------------+
      |                |
      v                v
  human_approval      END
  (APPROVAL_REQUIRED)  (ALLOWED)

The critical hand-off: LangGraph NEVER decides to block on its own. It *requests*
containment and passes its Jev-derived state to the MCP server, where the Keydris
policy engine has the final say.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Annotated, Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from clients.mcp_client import MCPEnforcerClient
from governance.config import (
    DEFAULT_INVESTIGATOR_MODEL,
    DEFAULT_OPENROUTER_BASE_URL,
    get_env,
    openrouter_api_key,
)
from governance.jev_client import JevClient
from governance.schemas import (
    GovernanceContext,
    GovernanceDecision,
    JevClassification,
    ThreatVerdict,
)

DATA_DIR = Path(__file__).resolve().parent / "data"
ALERTS_FILE = DATA_DIR / "alerts.json"


# ---------------------------------------------------------------------------
# Graph state
# ---------------------------------------------------------------------------


class AgentState(TypedDict, total=False):
    """Typed state threaded through the graph.

    """

    alert: dict[str, Any]          # the inbound security alert
    log_summary: str               # investigate: LLM's contextual summary
    investigation_model: str       # which LLM produced the summary
    jev: dict[str, Any]            # judge: serialized JevClassification
    governance_decision: str       # enforcer: GovernanceDecision value
    enforcer_response: dict[str, Any]  # enforcer: serialized ToolResponse
    approval_ticket: dict[str, Any]    # human_approval: the escalation record


# ---------------------------------------------------------------------------
# External dependencies (injectable for tests)
# ---------------------------------------------------------------------------


def get_investigator_llm() -> Any:
    """Build the reasoning LLM: OpenRouter chat completions.

    Defaults to DeepSeek V4.1 Flash per the project brief; override with
    ``LLM_MODEL_NAME`` in ``.env``.
    """

    from langchain_openai import ChatOpenAI

    model = get_env("LLM_MODEL_NAME", DEFAULT_INVESTIGATOR_MODEL)
    base_url = get_env("OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL)
    return ChatOpenAI(
        model=model,
        base_url=base_url,
        api_key=openrouter_api_key(),
        temperature=0,
    )


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_INVESTIGATOR_SYSTEM = (
    "You are a senior SecOps investigator. Read the raw security logs and write "
    "a brief, factual contextual summary of the threat: what happened, how "
    "strong the signal is, and what (if anything) is suspicious. Do not invent "
    "facts and do not recommend an action. Three to five sentences."
)


def _format_alert(alert: dict[str, Any]) -> str:
    logs = alert.get("raw_logs") or []
    logs_text = "\n".join(str(line) for line in logs)
    return (
        f"alert_id: {alert.get('alert_id')}\n"
        f"source: {alert.get('source')}\n"
        f"severity: {alert.get('severity')}\n"
        f"src_ip: {alert.get('src_ip')}\n"
        f"target: {alert.get('target')}\n"
        f"description: {alert.get('description')}\n\n"
        f"raw_logs:\n{logs_text}"
    )


# ---------------------------------------------------------------------------
# Conditional-edge routing (module-level so it is unit-testable)
# ---------------------------------------------------------------------------


def route_after_judge(state: AgentState) -> Literal["enforcer", "no_action"]:
    """Any potentially actionable verdict goes to the enforcer.

    We deliberately route both malicious AND suspicious to the MCP server so
    Keydris — not the graph — is the authority that decides auto-block vs
    approval (defense in depth). Only a benign verdict short-circuits.
    """

    verdict = state["jev"]["verdict"]
    if verdict == ThreatVerdict.BENIGN.value:
        return "no_action"
    return "enforcer"


def route_after_enforcer(state: AgentState) -> Literal["human_approval", "done"]:
    """Escalate to a human only when Keydris intercepted the call."""

    status = state.get("governance_decision")
    if status in {
        GovernanceDecision.APPROVAL_REQUIRED.value,
        GovernanceDecision.DENIED.value,
    }:
        return "human_approval"
    return "done"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_graph(
    *,
    llm: Any | None = None,
    jev: JevClient | None = None,
    enforcer: MCPEnforcerClient | None = None,
) -> Any:
    """Compile the LangGraph state machine.

    Dependencies are injectable so tests can supply fakes and avoid network.
    """

    _llm = llm if llm is not None else get_investigator_llm()
    _jev = jev if jev is not None else JevClient.from_env()
    _enforcer = enforcer if enforcer is not None else MCPEnforcerClient.from_env()

    # -- Node 1: Investigator (LLM) ----------------------------------------

    async def investigate(state: AgentState) -> dict[str, Any]:
        alert = state["alert"]
        messages = [
            ("system", _INVESTIGATOR_SYSTEM),
            ("user", _format_alert(alert)),
        ]
        response = await _llm.ainvoke(messages)
        summary = response.content if isinstance(response.content, str) else str(response.content)
        return {
            "log_summary": summary.strip(),
            "investigation_model": getattr(_llm, "model_name", None)
            or get_env("LLM_MODEL_NAME", DEFAULT_INVESTIGATOR_MODEL),
        }

    # -- Node 2: Judge (Jev Choice primitive) ------------------------------

    async def judge(state: AgentState) -> dict[str, Any]:
        alert = state["alert"]
        classification: JevClassification = _jev.classify_threat(
            alert, state.get("log_summary", "")
        )
        return {"jev": classification.model_dump(mode="json")}

    # -- Node 3: Enforcer (Keydris-gated MCP call) -------------------------

    async def enforcer(state: AgentState) -> dict[str, Any]:
        alert = state["alert"]
        jev = state["jev"]
        ip = alert["src_ip"]

        # Assemble the agent's typed claim for the MCP server. Keydris validates
        # and authorizes this before any containment side effect can occur.
        governance = GovernanceContext(
            alert_id=alert["alert_id"],
            principal="secops-agent",
            action="block_ip",
            target=ip,
            verdict=ThreatVerdict(jev["verdict"]),
            confidence=float(jev["confidence"]),
            probabilities=jev.get("probabilities", {}),
            rationale=jev.get("rationale", ""),
        )

        response = await _enforcer.call_block_ip(
            ip=ip,
            reason=(
                f"Jev verdict={jev['verdict']} confidence={jev['confidence']:.4f} "
                f"for alert {alert['alert_id']}"
            ),
            governance=governance.model_dump(mode="json"),
        )
        return {
            "enforcer_response": response,
            "governance_decision": response.get("status"),
        }

    # -- Node 4a: Human approval (escalation) ------------------------------

    async def human_approval(state: AgentState) -> dict[str, Any]:
        alert = state["alert"]
        jev = state["jev"]
        ticket = {
            "ticket_id": f"APR-{uuid.uuid4().hex[:8].upper()}",
            "status": "PENDING_HUMAN_APPROVAL",
            "alert_id": alert["alert_id"],
            "requested_action": "block_ip",
            "target": alert["src_ip"],
            "jev_verdict": jev["verdict"],
            "jev_confidence": jev["confidence"],
            "investigator_summary": state.get("log_summary", ""),
            "interception": state.get("enforcer_response", {}).get("message", ""),
        }
        return {"approval_ticket": ticket}

    # -- Node 4b: No action (confidently benign) ---------------------------

    async def no_action(state: AgentState) -> dict[str, Any]:
        return {
            "governance_decision": GovernanceDecision.NO_ACTION.value,
            "enforcer_response": {
                "status": GovernanceDecision.NO_ACTION.value,
                "executed": False,
                "tool": "block_ip",
                "message": "Confidently benign; no containment action taken.",
                "payload": {},
            },
        }

    # -- Wire it up ---------------------------------------------------------

    graph: StateGraph = StateGraph(AgentState)
    graph.add_node("investigate", investigate)
    graph.add_node("judge", judge)
    graph.add_node("enforcer", enforcer)
    graph.add_node("human_approval", human_approval)
    graph.add_node("no_action", no_action)

    graph.add_edge(START, "investigate")
    graph.add_edge("investigate", "judge")
    graph.add_conditional_edges(
        "judge",
        route_after_judge,
        {"enforcer": "enforcer", "no_action": "no_action"},
    )
    graph.add_conditional_edges(
        "enforcer",
        route_after_enforcer,
        {"human_approval": "human_approval", "done": END},
    )
    graph.add_edge("human_approval", END)
    graph.add_edge("no_action", END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def load_alerts(path: Path = ALERTS_FILE) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


async def run_alert(alert: dict[str, Any], *, graph: Any | None = None) -> AgentState:
    """Run a single alert through the compiled graph."""

    compiled = graph if graph is not None else build_graph()
    return await compiled.ainvoke({"alert": alert})