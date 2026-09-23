"""Jev / TypeSafe System One client.

Jev is a *decision* model: it does not generate text, it answers typed questions
about a `state` you send and returns a value plus a probability distribution.
We use exactly one question — a ``choice`` over ``benign | suspicious | malicious``
— because a single Choice answer already carries both the label (`choice`) and a
`confidence` scalar.

Wire format (see documentation/jev_typesafe.md and documentation/jev_SDK):

    POST {OPENROUTER_BASE_URL}/systemone
    Authorization: Bearer $OPENROUTER_API_KEY
    {
      "model": "typesafe/jev-1.13",
      "state":  "<free-form description of the situation>",
      "questions": {
        "threat_verdict": {
          "type": "choice",
          "instructions": "...",
          "criteria": { "benign": "...", "suspicious": "...", "malicious": "..." }
        }
      }
    }

    -> { "answers": { "threat_verdict": { "type": "choice", "choice": "...",
                                          "confidence": 0.97,
                                          "probabilities": { ... } } } }

Fail-closed policy: any transport error, HTTP error, or schema violation yields
``suspicious`` with ``confidence=0.0``. A degraded classifier must never be able
to unlock an automatic containment action.
"""

from __future__ import annotations

from typing import Any

import httpx

from .config import (
    DEFAULT_JEV_MODEL,
    DEFAULT_JEV_PATH,
    DEFAULT_OPENROUTER_BASE_URL,
    get_env,
    openrouter_api_key,
)
from .schemas import JevChoiceAnswer, JevClassification, ThreatVerdict

# The one Choice question the Judge node asks.
VERDICT_QUESTION = "threat_verdict"

_VERDICT_CRITERIA = {
    "benign": (
        "Normal, expected behavior. Logins or traffic consistent with the user's "
        "baseline, known good infrastructure, or clearly explained by policy."
    ),
    "suspicious": (
        "Anomalous or ambiguous activity that could be an attack but lacks clear "
        "evidence. Warrants human review before any containment."
    ),
    "malicious": (
        "Clear evidence of an active attack or confirmed compromise, such as "
        "sustained credential brute forcing, successful login after many failures "
        "from an untrusted source, or known-bad indicators."
    ),
}


class JevClassificationError(RuntimeError):
    """Raised only for programmer errors; runtime failures fail closed instead."""


class JevClient:
    """Thin, typed client over the Jev Choice primitive."""

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str = DEFAULT_OPENROUTER_BASE_URL,
        model: str = DEFAULT_JEV_MODEL,
        path: str = DEFAULT_JEV_PATH,
        timeout: float = 30.0,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._path = path if path.startswith("/") else f"/{path}"
        self._timeout = timeout

    # -- construction -------------------------------------------------------

    @classmethod
    def from_env(cls) -> "JevClient":
        return cls(
            api_key=openrouter_api_key(),
            base_url=get_env("OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL),
            model=get_env("TYPESAFE_MODEL_NAME", DEFAULT_JEV_MODEL),
            path=get_env("JEV_PATH", DEFAULT_JEV_PATH),
        )

    @property
    def endpoint(self) -> str:
        return f"{self._base_url}{self._path}"

    # -- state construction -------------------------------------------------

    @staticmethod
    def build_state(alert: dict[str, Any], summary: str) -> str:
        """Flatten the alert + LLM summary into Jev's natural-language `state`.

        Jev cannot see the LangGraph state object; it only sees this string, so we
        include every signal a human analyst would weigh.
        """

        logs = alert.get("raw_logs") or []
        if isinstance(logs, (list, tuple)):
            logs_text = "\n".join(str(line) for line in logs)
        else:
            logs_text = str(logs)

        return (
            f"Security alert {alert.get('alert_id', 'unknown')}\n"
            f"Source: {alert.get('source', 'unknown')}\n"
            f"Reported severity: {alert.get('severity', 'unknown')}\n"
            f"Source IP: {alert.get('src_ip', 'unknown')}\n"
            f"Target asset: {alert.get('target', 'unknown')}\n\n"
            f"Investigator summary:\n{summary}\n\n"
            f"Raw log lines:\n{logs_text}"
        )

    # -- the Choice call ----------------------------------------------------

    def classify_threat(self, alert: dict[str, Any], summary: str) -> JevClassification:
        """Ask Jev for a typed threat verdict. Never raises on API failure."""

        state = self.build_state(alert, summary)
        request_body = {
            "model": self._model,
            "state": state,
            "questions": {
                VERDICT_QUESTION: {
                    "type": "choice",
                    "instructions": (
                        "Classify the security situation described in the state as "
                        "benign, suspicious, or malicious."
                    ),
                    "criteria": _VERDICT_CRITERIA,
                }
            },
        }

        try:
            response = httpx.post(
                self.endpoint,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json=request_body,
                timeout=self._timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            # Surface the provider's error body (e.g. OpenRouter routing policy)
            # so operators can act on it instead of seeing an opaque failure.
            detail = ""
            try:
                detail = exc.response.text[:500]
            except Exception:  # noqa: BLE001 - best-effort diagnostics only
                pass
            return self._fail_closed(
                f"Jev HTTP {exc.response.status_code} from {self.endpoint}: {detail}"
            )
        except (httpx.HTTPError, ValueError) as exc:
            return self._fail_closed(f"Jev transport/parse failure: {exc!r}")

        try:
            answers = payload.get("answers") or {}
            raw_answer = answers.get(VERDICT_QUESTION)
            if not raw_answer:
                raise ValueError(f"missing {VERDICT_QUESTION!r} in Jev answers")

            answer = JevChoiceAnswer.model_validate(raw_answer)

            # Guard the label against the strict enum: anything else fails closed.
            verdict = ThreatVerdict(answer.choice)

            return JevClassification(
                verdict=verdict,
                confidence=answer.confidence,
                probabilities=answer.probabilities,
                rationale=(
                    f"Jev choice={verdict.value} confidence={answer.confidence:.4f} "
                    f"probabilities={answer.probabilities}"
                ),
                model=payload.get("model"),
                usage=payload.get("usage") or {},
                failed_closed=False,
                raw=payload,
            )
        except (ValueError, KeyError) as exc:
            return self._fail_closed(f"Jev response failed validation: {exc!r}")

    # -- fail-closed helper -------------------------------------------------

    def _fail_closed(self, reason: str) -> JevClassification:
        return JevClassification(
            verdict=ThreatVerdict.SUSPICIOUS,
            confidence=0.0,
            probabilities={},
            rationale=f"FAIL-CLOSED: {reason}",
            model=self._model,
            failed_closed=True,
            raw={},
        )