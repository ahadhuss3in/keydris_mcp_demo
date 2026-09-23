"""End-to-end demo: run every mock alert through the governed pipeline.

Usage:
    python run_demo.py                    # run all alerts in data/alerts.json
    python run_demo.py --alert-id ALT-2026-0001
    python run_demo.py --transport inprocess

Expected outcomes (Jev is live and slightly stochastic, so labels can vary):
    ALT-2026-0001  -> auto-block         (malicious, high confidence)
    ALT-2026-0002  -> human approval     (suspicious)
    ALT-2026-0003  -> no action          (benign)
    ALT-2026-0004  -> human approval     (ambiguous / low confidence)
"""

from __future__ import annotations

import argparse
import asyncio

from agent_workflow import build_graph, load_alerts
from clients.mcp_client import MCPEnforcerClient

BAR = "=" * 78


def _print_result(alert: dict, state: dict, transport: str) -> None:
    jev = state.get("jev", {})
    response = state.get("enforcer_response", {})
    decision = state.get("governance_decision") or response.get("status", "UNKNOWN")
    ticket = state.get("approval_ticket")

    print(BAR)
    print(f"ALERT   : {alert['alert_id']}  ({alert['severity']})  src={alert['src_ip']}")
    print(f"EXPECTED: {alert.get('expected_path', 'n/a')}")
    print("-" * 78)
    print(f"Investigator summary:\n  {state.get('log_summary', '').strip()}")
    print("-" * 78)
    print(
        f"Jev verdict : {jev.get('verdict')}  confidence={jev.get('confidence')}  "
        f"(failed_closed={jev.get('failed_closed')})"
    )
    if jev.get("failed_closed"):
        print(f"Jev failure : {jev.get('rationale')}")
    print(f"Decision    : {decision}")
    print(f"Executed    : {response.get('executed')}  [transport={transport}]")
    print(f"Detail      : {response.get('message', '')}")
    if response.get("executed"):
        print(f"Enforcement : {response.get('payload')}")
    if ticket:
        print(f"Approval    : {ticket['ticket_id']} -> {ticket['status']}")


async def main() -> None:
    parser = argparse.ArgumentParser(description="Governed SecOps Agent demo")
    parser.add_argument("--alert-id", help="run only this alert id")
    parser.add_argument(
        "--transport",
        choices=["stdio", "inprocess"],
        help="override the MCP transport (default: from ENFORCER_TRANSPORT)",
    )
    args = parser.parse_args()

    alerts = load_alerts()
    if args.alert_id:
        alerts = [a for a in alerts if a["alert_id"] == args.alert_id]
        if not alerts:
            raise SystemExit(f"no alert with id {args.alert_id!r}")

    enforcer = MCPEnforcerClient.from_env()
    if args.transport:
        enforcer.transport = args.transport

    graph = build_graph(enforcer=enforcer)

    for alert in alerts:
        try:
            state = await graph.ainvoke({"alert": alert})
        except Exception as exc:  # noqa: BLE001 - keep the demo running
            print(BAR)
            print(f"ALERT {alert['alert_id']} FAILED: {exc.__class__.__name__}: {exc}")
            continue
        _print_result(alert, state, enforcer.last_transport_used or enforcer.transport)

    print(BAR)


if __name__ == "__main__":
    asyncio.run(main())