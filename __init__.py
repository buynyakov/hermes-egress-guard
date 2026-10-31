"""egress-guard: stop AI-agent tool calls from sending secrets or personal data to untrusted hosts.

Two layers, both configured under ``plugins.entries.egress-guard.settings`` in config.yaml:

1. ``pre_tool_call`` hook: scans terminal commands, execute_code scripts and URL tools for network
   activity that carries secret environment variables, secret files, literal keys or personal terms,
   and logs, asks for human approval, or blocks the call.
2. Environment stripping: variables in ``strip_env_keys`` are removed from execute_code / background
   subprocesses (through a terminal-environment provider that is never selectable as a backend) and
   unset at the start of every terminal command.

The hook fails open: an internal error is logged and the tool call proceeds unchanged.
"""
from __future__ import annotations

import importlib.util
import logging
import sys
import time
from pathlib import Path

log = logging.getLogger("egress_guard")

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("egress_guard_engine", _here / "guard.py")
guard = importlib.util.module_from_spec(_spec)
sys.modules["egress_guard_engine"] = guard
_spec.loader.exec_module(guard)

_UNSET_MARK = "# egress-guard\n"
_CACHE_TTL = 2.0


class EgressGuard:
    """Hook and provider state bound to one plugin context."""

    def __init__(self, ctx=None):
        self._ctx = ctx
        self._cfg = None
        self._loaded_at = 0.0
        self._warned_keys: set = set()

    # ------------------------------------------------------------------ config
    def config(self) -> dict:
        now = time.monotonic()
        if self._cfg is not None and now - self._loaded_at < _CACHE_TTL:
            return self._cfg
        raw = {}
        if self._ctx is not None:
            for key in guard.DEFAULTS:
                try:
                    value = self._ctx.get_config(key, None)
                except Exception:
                    value = None
                if value is not None:
                    raw[key] = value
        cfg = guard.merge_config(None)
        for key, value in raw.items():
            try:
                cfg.update(guard.validate_config({key: value}))
            except ValueError as exc:
                if key not in self._warned_keys:
                    self._warned_keys.add(key)
                    log.warning("egress-guard: ignoring invalid setting %s (%s); using the default", key, exc)
        self._cfg, self._loaded_at = cfg, now
        return cfg

    # ------------------------------------------------------------------ hook
    def pre_tool_call(self, tool_name, args, **_kwargs):
        try:
            cfg = self.config()
            res = guard.evaluate(tool_name, args, cfg)
            if res["action"] != "off":
                self._record(tool_name, args, res, cfg)
                if res["action"] == "block":
                    return {"action": "block", "message": res["message"]}
                if res["action"] == "ask":
                    kinds = "+".join(sorted({f["type"] for f in res["findings"]}))
                    return {"action": "approve", "message": res["message"], "rule_key": f"egress-guard:{kinds}"}
            return self._unset_directive(tool_name, args, cfg)
        except Exception:
            log.warning("egress-guard: evaluation failed; allowing the call (fail-open)", exc_info=True)
            return None

    def _unset_directive(self, tool_name, args, cfg):
        if not (cfg.get("enabled") and cfg.get("unset_in_terminal")):
            return None
        if tool_name not in cfg["scan_tools_command"] or not isinstance(args, dict):
            return None
        cmd = args.get("command")
        prefix = guard.unset_prefix(cfg.get("strip_env_keys"))
        if not prefix or not isinstance(cmd, str) or not cmd or cmd.startswith(_UNSET_MARK):
            return None
        return {"action": "modify", "args": {"command": f"{_UNSET_MARK}{prefix}{cmd}"}}

    def _record(self, tool_name, args, res, cfg):
        text = guard.scan_text(tool_name, args, cfg) or ""
        kinds = ", ".join(f"{f['type']}={f['detail']}" for f in res["findings"])
        level = logging.WARNING if res["action"] in ("ask", "block") else logging.INFO
        log.log(level, "egress-guard %s tool=%s hosts=%s findings=[%s] snippet=%r", res["action"], tool_name,
                ",".join(res["hosts"]) or "-", kinds, guard.scrub(text, cfg))

    # ------------------------------------------------------------------ env stripping
    def strip_keys(self) -> frozenset:
        try:
            cfg = self.config()
            return frozenset(cfg.get("strip_env_keys") or ()) if cfg.get("enabled") else frozenset()
        except Exception:
            return frozenset()


def _make_provider(state: EgressGuard):
    from agent.terminal_env_provider import TerminalEnvironmentProvider

    class EgressGuardEnv(TerminalEnvironmentProvider):
        """Publishes strip_env_keys only; is_available() is False so it is never used as a backend."""

        name = "egress_guard_env"
        display_name = "egress-guard (environment stripping)"

        @property
        def strip_env_keys(self):
            return state.strip_keys()

        def is_available(self):
            return False

        def create_environment(self, **kwargs):
            raise RuntimeError("egress_guard_env is not an execution backend")

    return EgressGuardEnv()


def register(ctx):
    state = EgressGuard(ctx)
    ctx.register_hook("pre_tool_call", state.pre_tool_call)
    try:
        ctx.register_terminal_environment_provider(_make_provider(state))
    except Exception:
        log.warning("egress-guard: environment-stripping provider unavailable; the hook still runs",
                    exc_info=True)
    return state
