"""Typed contracts shared across the three planes of the PoC.

    LangGraph (System 2 reasoning)  ->  Jev (System 1 decision)  ->  Keydris (execution gate)

Every boundary between those three systems is a Pydantic model. That is the
whole point of the PoC: the agent cannot smuggle free-form text across a trust
boundary. The LLM produces prose; Jev collapses it to a *typed* verdict; Keydris
only ever reasons over typed fields.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Jev / TypeSafe primitives
# ---------------------------------------------------------------------------


class ThreatVerdict(str, Enum):
    """The ONLY three labels Jev is allowed to return for the threat question."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class JevChoiceAnswer(BaseModel):
    """A Jev ``choice`` answer, e.g. ``answers["threat_verdict"]``.

    ``confidence`` summarises how concentrated the probability distribution is
    (see Jev docs). It is NOT a calibrated probability that the action is safe,
    which is why the policy threshold below is a deliberate, tunable constant.
    """

    type: Literal["choice"] = "choice"
    choice: str
    confidence: float = Field(ge=0.0, le=1.0)
    probabilities: dict[str, float] = Field(default_factory=dict)


class JevClassification(BaseModel):
    """Normalized, validated view of the Jev Judge result.

    This is what the LangGraph state stores and what Keydris reads. Keeping the
    raw provider response around (`raw`) aids audit/debugging without letting
    the graph branch on un-typed data.
    """

    verdict: ThreatVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    probabilities: dict[str, float] = Field(default_factory=dict)
    rationale: str = ""
    model: str | None = None
    usage: dict[str, Any] = Field(default_factory=dict)
    failed_closed: bool = False
    raw: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Keydris / enforcement contracts
# ---------------------------------------------------------------------------


class GovernanceContext(BaseModel):
    """The agent's assertion handed to the MCP server.

    In production Keydris would receive this as *signed* request metadata. In
    the PoC it travels as the ``governance`` argument of the ``block_ip`` tool;
    the keydris-reader middleware lifts it into request-scoped context and the
    policy engine treats it as untrusted-until-validated.
    """

    alert_id: str
    principal: str = "secops-agent"
    action: Literal["block_ip"] = "block_ip"
    target: str
    verdict: ThreatVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    probabilities: dict[str, float] = Field(default_factory=dict)
    rationale: str = ""


class GovernanceDecision(str, Enum):
    """Outcome of the Keydris policy engine."""

    ALLOWED = "ALLOWED"                    # auto-execute
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"  # intercepted, human in the loop
    NO_ACTION = "NO_ACTION"                # confident benign, nothing to contain
    DENIED = "DENIED"                      # malformed / missing governance context


class ToolResponse(BaseModel):
    """Uniform payload returned by every guarded MCP tool."""

    status: GovernanceDecision
    executed: bool
    tool: str
    target: str | None = None
    message: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)