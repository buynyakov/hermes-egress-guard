"""Shared pytest fixtures: the engine, the plugin entrypoint and a stand-in Hermes plugin context."""
import abc
import importlib.util
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name, path, **kw):
    spec = importlib.util.spec_from_file_location(name, path, **kw)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _ensure_provider_base():
    """Install a stub agent.terminal_env_provider when Hermes itself is not importable."""
    try:
        import agent.terminal_env_provider  # noqa: F401
        return
    except Exception:
        pass
    pkg = types.ModuleType("agent")
    pkg.__path__ = []
    mod = types.ModuleType("agent.terminal_env_provider")

    class TerminalEnvironmentProvider(abc.ABC):
        @property
        def strip_env_keys(self):
            return frozenset()

        @abc.abstractmethod
        def is_available(self):
            ...

    mod.TerminalEnvironmentProvider = TerminalEnvironmentProvider
    sys.modules["agent"] = pkg
    sys.modules["agent.terminal_env_provider"] = mod


class FakeCtx:
    """Mimics the slice of Hermes' PluginContext the plugin uses."""

    def __init__(self, settings=None, provider_error=False):
        self.settings = dict(settings or {})
        self.hooks = {}
        self.providers = []
        self.provider_error = provider_error

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_hook(self, name, cb):
        self.hooks[name] = cb

    def register_terminal_environment_provider(self, provider):
        if self.provider_error:
            raise RuntimeError("not supported")
        self.providers.append(provider)


@pytest.fixture(scope="session")
def guard():
    return _load("egress_guard_engine_pytest", ROOT / "guard.py")


@pytest.fixture(scope="session")
def plugin():
    _ensure_provider_base()
    return _load("egress_guard_plugin_pytest", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])


@pytest.fixture
def make_plugin(plugin):
    """make_plugin(settings) -> (ctx, state, pre_tool_call hook)."""
    def factory(settings=None, **kw):
        ctx = FakeCtx(settings, **kw)
        state = plugin.register(ctx)
        return ctx, state, ctx.hooks["pre_tool_call"]
    return factory


@pytest.fixture
def cfg(guard):
    """Engine config with a strip key and fake personal terms (no real data)."""
    return guard.merge_config({"strip_env_keys": ["PAYMENTS_KEY"], "pii_terms": ["jane.doe@example.org"]})


@pytest.fixture
def ev(guard, cfg):
    def run(text, tool="terminal", config=None):
        key = "code" if tool == "execute_code" else "command"
        return guard.evaluate(tool, {key: text}, config or cfg)
    return run
