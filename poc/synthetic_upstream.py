"""In-memory oracle for effects executed by the synthetic STF demo.

The policy gateway decides whether an action is allowed. This component only
records an effect after the gateway calls ``execute``; it never calls a real
service or performs a case write or document export.
"""
from __future__ import annotations

import hashlib
import json
import threading
from copy import deepcopy
from typing import Any


EFFECT_KINDS = {
    "case_write": "SYNTHETIC_CASE_WRITE",
    "export_restricted": "DOCUMENT_EXPORT_SYNTHETIC",
}


class SyntheticUpstream:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._effects: list[dict[str, Any]] = []

    @property
    def hits(self) -> int:
        with self._lock:
            return len(self._effects)

    @property
    def effects(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(self._effects)

    def reset(self) -> None:
        with self._lock:
            self._effects.clear()

    def execute(self, action: str, principal: str, target: str,
                parameters: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(action, str) or action not in EFFECT_KINDS:
            raise ValueError("unsupported synthetic upstream action")
        if not isinstance(principal, str) or not principal.strip():
            raise ValueError("principal must be a non-empty string")
        if not isinstance(target, str) or not target.strip():
            raise ValueError("target must be a non-empty string")
        if not isinstance(parameters, dict):
            raise ValueError("parameters must be an object")

        canonical = json.dumps(
            parameters, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()

        with self._lock:
            effect = {
                "effect_id": f"EFF-{len(self._effects) + 1:06d}",
                "status": "EXECUTED",
                "synthetic": True,
                "action": action,
                "effect_kind": EFFECT_KINDS[action],
                "principal": principal,
                "target": target,
                "parameters_digest": digest,
            }
            self._effects.append(effect)
            return deepcopy(effect)
