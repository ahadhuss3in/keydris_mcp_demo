"""Guardrail tests: policy boundaries, the Keydris intercept, and graph routing.

These tests are pure logic — no network, no LLM, no MCP subprocess — so they run
fast and deterministically. They are the safety net for the *authorization*
behavior, which is the whole point of the PoC.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from governance.jev_client import JevClient
from governance.keydris import (
    PolicyEngine,
    bind_governance_context,
    keydris_guard,
    reset_governance_context,
)
from governance.schemas import (
    GovernanceContext,
    GovernanceDecision,
    JevChoiceAnswer,
    ThreatVerdict,
)

THRESHOLD = 0.90


def make_ctx(verdict: ThreatVerdict, confidence: float) -> GovernanceContext:
    return GovernanceContext(
        alert_id="ALT-TEST",
        target="203.0.113.9",
        verdict=verdict,
        confidence=confidence,
    )


# ---------------------------------------------------------------------------
# Policy engine boundaries
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("verdict", "confidence", "expected"),
    [
        # auto-block: the only ALLOWED path
        (ThreatVerdict.MALICIOUS, 0.91, GovernanceDecision.ALLOWED),
        (ThreatVerdict.MALICIOUS, 0.99, GovernanceDecision.ALLOWED),
        # boundary is deliberately fail-closed
        (ThreatVerdict.MALICIOUS, 0.90, GovernanceDecision.APPROVAL_REQUIRED),
        (ThreatVerdict.MALICIOUS, 0.50, GovernanceDecision.APPROVAL_REQUIRED),
        # suspicious always escalates, even at high confidence
        (ThreatVerdict.SUSPICIOUS, 0.99, GovernanceDecision.APPROVAL_REQUIRED),
        (ThreatVerdict.SUSPICIOUS, 0.30, GovernanceDecision.APPROVAL_REQUIRED),
        # confidently benign -> no containment
        (ThreatVerdict.BENIGN, 0.95, GovernanceDecision.NO_ACTION),
        # low-confidence benign -> human
        (ThreatVerdict.BENIGN, 0.50, GovernanceDecision.APPROVAL_REQUIRED),
    ],
)
def test_policy_engine_boundaries(verdict, confidence, expected):
    engine = PolicyEngine(THRESHOLD)
    assert engine.evaluate(make_ctx(verdict, confidence)) == expected


def test_policy_engine_denies_missing_context():
    assert PolicyEngine(THRESHOLD).evaluate(None) == GovernanceDecision.DENIED


def test_policy_threshold_is_tunable():
    engine = PolicyEngine(0.50)
    # 0.60 malicious would escalate at 0.90 but auto-blocks at a 0.50 threshold.
    assert engine.evaluate(make_ctx(ThreatVerdict.MALICIOUS, 0.60)) == GovernanceDecision.ALLOWED


# ---------------------------------------------------------------------------
# Keydris middleware: the tool body must not run unless ALLOWED
# ---------------------------------------------------------------------------


def _run_guard(ctx, engine=PolicyEngine(THRESHOLD)):
    calls: list[tuple] = []

    async def impl(ip, reason):
        calls.append((ip, reason))
        return {"action": "block_ip", "ip": ip, "rule_id": "fw-rule-test"}

    guarded = keydris_guard(engine)(impl)

    async def scenario():
        token = bind_governance_context(ctx)
        try:
            return await guarded("203.0.113.9", "unit test")
        finally:
            reset_governance_context(token)

    return asyncio.run(scenario()), calls


def test_guard_executes_when_allowed():
    ctx = make_ctx(ThreatVerdict.MALICIOUS, 0.97)
    response, calls = _run_guard(ctx)
    assert response["status"] == GovernanceDecision.ALLOWED.value
    assert response["executed"] is True
    assert calls, "impl should have been invoked"
    assert response["payload"]["rule_id"] == "fw-rule-test"


def test_guard_intercepts_when_approval_required():
    ctx = make_ctx(ThreatVerdict.SUSPICIOUS, 0.99)
    response, calls = _run_guard(ctx)
    assert response["status"] == GovernanceDecision.APPROVAL_REQUIRED.value
    assert response["executed"] is False
    assert calls == [], "impl must NOT be invoked when intercepted"
    assert response["payload"]["requires_human_approval"] is True


def test_guard_blocks_at_boundary_and_never_calls_impl():
    ctx = make_ctx(ThreatVerdict.MALICIOUS, 0.90)
    response, calls = _run_guard(ctx)
    assert response["status"] == GovernanceDecision.APPROVAL_REQUIRED.value
    assert calls == []


def test_guard_denies_without_context():
    calls: list[tuple] = []

    async def impl(ip, reason):  # pragma: no cover - must not run
        calls.append((ip, reason))
        return {}

    guarded = keydris_guard(PolicyEngine(THRESHOLD))(impl)
    response = asyncio.run(guarded("203.0.113.9", "no context"))
    assert response["status"] == GovernanceDecision.DENIED.value
    assert response["executed"] is False
    assert calls == []


# ---------------------------------------------------------------------------
# Jev client: fail-closed on any failure
# ---------------------------------------------------------------------------


def _fake_response(payload):
    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    return _Resp()


def test_jev_classify_parses_choice(monkeypatch):
    payload = {
        "model": "typesafe/jev-1.13-20260917",
        "answers": {
            "threat_verdict": {
                "type": "choice",
                "choice": "malicious",
                "confidence": 0.97,
                "probabilities": {"benign": 0.0, "suspicious": 0.03, "malicious": 0.97},
            }
        },
        "usage": {"cost": 0.00001},
    }
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _fake_response(payload))

    client = JevClient(api_key="test")
    result = client.classify_threat({"alert_id": "A", "src_ip": "1.2.3.4"}, "summary")
    assert result.verdict == ThreatVerdict.MALICIOUS
    assert result.confidence == pytest.approx(0.97)
    assert result.probabilities["malicious"] == pytest.approx(0.97)
    assert result.failed_closed is False


def test_jev_fails_closed_on_transport_error(monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("no route to host")

    monkeypatch.setattr(httpx, "post", boom)

    client = JevClient(api_key="test")
    result = client.classify_threat({"alert_id": "A", "src_ip": "1.2.3.4"}, "summary")
    assert result.verdict == ThreatVerdict.SUSPICIOUS
    assert result.confidence == 0.0
    assert result.failed_closed is True


def test_jev_fails_closed_on_unknown_label(monkeypatch):
    payload = {
        "answers": {
            "threat_verdict": {"type": "choice", "choice": "catastrophic", "confidence": 0.99}
        }
    }
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _fake_response(payload))

    client = JevClient(api_key="test")
    result = client.classify_threat({"alert_id": "A", "src_ip": "1.2.3.4"}, "summary")
    assert result.failed_closed is True
    assert result.verdict == ThreatVerdict.SUSPICIOUS


def test_jev_choice_answer_validates_confidence_range():
    with pytest.raises(Exception):
        JevChoiceAnswer.model_validate(
            {"type": "choice", "choice": "benign", "confidence": 1.5}
        )


# ---------------------------------------------------------------------------
# Graph routing
# ---------------------------------------------------------------------------


def test_route_after_judge():
    from agent_workflow import route_after_judge

    assert route_after_judge({"jev": {"verdict": "benign"}}) == "no_action"
    assert route_after_judge({"jev": {"verdict": "suspicious"}}) == "enforcer"
    assert route_after_judge({"jev": {"verdict": "malicious"}}) == "enforcer"


def test_route_after_enforcer():
    from agent_workflow import route_after_enforcer

    assert route_after_enforcer({"governance_decision": "APPROVAL_REQUIRED"}) == "human_approval"
    assert route_after_enforcer({"governance_decision": "DENIED"}) == "human_approval"
    assert route_after_enforcer({"governance_decision": "ALLOWED"}) == "done"
    assert route_after_enforcer({"governance_decision": "NO_ACTION"}) == "done"