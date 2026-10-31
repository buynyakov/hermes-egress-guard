"""Consistency checks between guard.DEFAULTS, settings.default.yaml and plugin.yaml.

Standard library only: settings.default.yaml stores each value as one-line JSON, and plugin.yaml
is checked for its config_schema key names, so no YAML parser is needed.
"""
import importlib.util
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("egress_guard_engine_cfg", ROOT / "guard.py")
g = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(g)

_SETTING_RE = re.compile(r"^ {8}([a-z_]+): (.+)$")
_SCHEMA_KEY_RE = re.compile(r"^  ([a-z_]+): \{")


def _default_file_settings() -> dict:
    out = {}
    for line in (ROOT / "settings.default.yaml").read_text(encoding="utf-8").splitlines():
        m = _SETTING_RE.match(line)
        if m:
            out[m.group(1)] = json.loads(m.group(2))
    return out


def _schema_keys() -> list:
    keys, in_schema = [], False
    for line in (ROOT / "plugin.yaml").read_text(encoding="utf-8").splitlines():
        if line.startswith("config_schema:"):
            in_schema = True
            continue
        if in_schema:
            if line and not line.startswith(" "):
                break
            m = _SCHEMA_KEY_RE.match(line)
            if m:
                keys.append(m.group(1))
    return keys


class DefaultSettingsFile(unittest.TestCase):
    def test_matches_engine_defaults(self):
        self.assertEqual(_default_file_settings(), g.DEFAULTS)

    def test_validates(self):
        self.assertEqual(g.validate_config(_default_file_settings()), g.DEFAULTS)

    def test_nested_under_plugin_entry(self):
        text = (ROOT / "settings.default.yaml").read_text(encoding="utf-8")
        self.assertIn("plugins:\n  entries:\n    egress-guard:\n      settings:\n", text)


class ManifestSchema(unittest.TestCase):
    def test_schema_covers_every_setting(self):
        keys = _schema_keys()
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(set(keys), set(g.DEFAULTS))

    def test_manifest_name_matches_settings_path(self):
        text = (ROOT / "plugin.yaml").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^name: egress-guard$")
        self.assertRegex(text, r"(?m)^entrypoint: __init__$")
        self.assertRegex(text, r"(?m)^provides_hooks:\n  - pre_tool_call$")


if __name__ == "__main__":
    unittest.main()
