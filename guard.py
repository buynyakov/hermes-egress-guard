"""Detection engine for egress-guard.

Pure standard-library code with no Hermes imports, so it can be unit-tested on its own.

For every scanned tool call it answers one question: does this command, code or URL send
a secret or a listed personal term to a destination the user has not trusted?
Findings carry variable names, finding types and hosts, never the secret value itself.
"""
from __future__ import annotations

import copy
import json
import re

LEVELS = ("off", "log", "ask", "block")
HOST_DECISIONS = ("allow", "ask", "deny")
LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})

DEFAULTS: dict = {
    "enabled": True,
    # Response per finding type: off = ignore, log = record only, ask = human approval, block = veto.
    "mode_secret_env": "ask",        # $OPENAI_API_KEY, os.environ["X"], process.env.X sent to an untrusted host
    "mode_secret_file": "block",     # .env, ~/.ssh/, .netrc, credential JSON ... named in a network command
    "mode_literal_secret": "block",  # a literal API key / token / private key inside a network command
    "mode_pii": "ask",               # one of your pii_terms inside a network command
    "mode_unknown_host_env": "off",  # any env-var reference sent to an untrusted host (audit mode, noisy)
    # Variables removed from execute_code / background subprocess environments and unset in terminal commands.
    "strip_env_keys": [],
    "unset_in_terminal": True,
    # Extra names treated as secret (case-insensitive regex), on top of strip_env_keys.
    "secret_name_regex": (r"(?:api[_-]?key|token|secret|passw(?:or)?d|passwd|credential"
                          r"|private[_-]?key|access[_-]?key)"),
    "secret_file_regex": (r"(?:(?<![A-Za-z0-9_])\.env\b|auth\.json|/credentials/|\.ssh/|\.netrc|\.pgpass"
                          r"|\.npmrc|\.pypirc|\.aws/credentials|\.git-credentials|\.config/gh/hosts\.yml"
                          r"|client_secret[\w.-]*\.json|id_(?:rsa|ed25519|ecdsa)|\.pem\b|-token\.json)"),
    # Hosts that may receive anything (exact or subdomain match). Keep this short.
    "trusted_hosts": ["localhost", "127.0.0.1", "::1"],
    # Hosts that may receive only the listed variables (exact or subdomain match).
    "host_var_allow": {
        "api.github.com": ["GH_TOKEN", "GITHUB_TOKEN"],
        "api.openai.com": ["OPENAI_API_KEY"],
        "api.anthropic.com": ["ANTHROPIC_API_KEY"],
        "api.telegram.org": ["TELEGRAM_BOT_TOKEN"],
        "slack.com": ["SLACK_BOT_TOKEN"],
    },
    # Per-host verdicts that override scanning: allow = may receive anything, ask = always ask, deny = always block.
    "host_rules": {},
    # Personal terms (email, name, address, phone ...) matched case-insensitively as literals.
    "pii_terms": [],
    # Which tools are scanned, and which argument holds the text.
    "scan_tools_command": ["terminal"],
    "scan_tools_code": ["execute_code"],
    "scan_tools_url": ["web_extract", "browser_navigate"],
}

_CMD_WORDS = (r"curl|wget|http|https|httpie|xh|nc|ncat|netcat|socat|telnet|ftp|sftp|scp|rsync|ssh"
              r"|aria2c|lynx|w3m|openssl\s+s_client")
# A network command must sit in command position (line start, after ; | & ( ` $( or a quote, optionally behind
# sudo/env/time/xargs ...), so prose or identifiers such as "host" or "fetcher" do not match.
_PREFIX = (r"(?:^|[;&|(`\n'\"]|\$\()\s*(?:(?:sudo|env|time|nohup|command|exec|xargs|timeout\s+\S+)\s+"
           r"(?:-\S+\s+)*)*")
NET_RE = re.compile(
    _PREFIX + r"(?:" + _CMD_WORDS + r")(?=\s|$|[;&|)`'\"])"
    r"|https?://|wss?://|ftp://"
    r"|\b(?:import|from)\s+(?:urllib|requests|httpx|aiohttp|http\.client|socket|websockets?)\b"
    r"|\burlopen\s*\(|\b(?:requests|httpx)\.(?:get|post|put|patch|delete|request|head)\s*\("
    r"|\bsocket\.(?:socket|create_connection)\b|\bnet\.connect\b|\bfetch\s*\(|\baxios\b|\bXMLHttpRequest\b"
    r"|\bnode-fetch\b|\brequire\(\s*['\"](?:https?|net)['\"]|\bInvoke-WebRequest\b|\bNet::HTTP\b",
    re.I | re.M)
_URL_HOST_RE = re.compile(r"(?:https?|wss?|ftp)://(?:[^/\s'\"@]+@)?(\[[0-9a-f:]+\]|[A-Za-z0-9._-]+)", re.I)
_SSH_CMD_RE = re.compile(_PREFIX + r"(ssh|scp|sftp|rsync)[ \t]+([^;&|\n]*)", re.I | re.M)
_RAW_SOCK_RE = re.compile(_PREFIX + r"(?:nc|ncat|netcat|telnet)[ \t]+((?:-\S+[ \t]+)*)([A-Za-z0-9][\w.-]*)",
                          re.I | re.M)
# Options that consume the next token, per command, so `ssh -p 2222 -i key user@host` resolves to host.
_SSH_ARG_OPTS = {"ssh": set("BbcDEeFIiJLlmOoPpQRSWw"), "sftp": set("BbcDFiJloPRSs"),
                 "scp": set("cDFiJloPS"), "rsync": set("eTfB")}
_HOSTTOK_RE = re.compile(r"(?:ssh://)?(?:[\w.+-]+@)?(\[[0-9a-f:]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)"
                         r"(?::\d+)?$", re.I)
_REMOTE_RE = re.compile(r"^(?:[\w.+-]+@)?([A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?):(?!//)", re.I)
_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*")
_VAR_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

LITERAL_SECRET_RES = [re.compile(p) for p in (
    r"sk-ant-[A-Za-z0-9_-]{20,}", r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}", r"gh[pousr]_[A-Za-z0-9]{30,}",
    r"github_pat_[A-Za-z0-9_]{30,}", r"glpat-[A-Za-z0-9_-]{20,}", r"AIza[0-9A-Za-z_-]{30,}",
    r"xox[abprs]-[A-Za-z0-9-]{10,}", r"AKIA[0-9A-Z]{16}", r"hf_[A-Za-z0-9]{30,}",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",
)]


# --------------------------------------------------------------------------- config

def merge_config(overrides: dict | None) -> dict:
    """DEFAULTS overlaid with known keys from `overrides` (unknown keys are ignored)."""
    cfg = copy.deepcopy(DEFAULTS)
    for key, value in (overrides or {}).items():
        if key in DEFAULTS and value is not None:
            cfg[key] = value
    return cfg


def validate_config(values: dict) -> dict:
    """Return a cleaned copy of `values`; raise ValueError on the first invalid setting."""
    out: dict = {}
    for key, default in DEFAULTS.items():
        if key not in values:
            continue
        value = values[key]
        if key.startswith("mode_"):
            if value not in LEVELS:
                raise ValueError(f"{key} must be one of {LEVELS}, got {value!r}")
        elif key == "host_rules":
            if not isinstance(value, dict):
                raise ValueError("host_rules must be a mapping of host -> allow|ask|deny")
            clean = {}
            for host, decision in value.items():
                host, decision = str(host).strip().lower(), str(decision).strip().lower()
                if not _HOST_RE.fullmatch(host) and host not in LOOPBACK:
                    raise ValueError(f"host_rules: {host!r} must be a bare host such as example.com")
                if decision not in HOST_DECISIONS:
                    raise ValueError(f"host_rules: decision for {host} must be one of {HOST_DECISIONS}")
                clean[host] = decision
            value = clean
        elif key == "host_var_allow":
            if not isinstance(value, dict) or not all(isinstance(v, list) for v in value.values()):
                raise ValueError("host_var_allow must be a mapping of host -> list of variable names")
            value = {str(h).strip().lower(): [str(x).strip() for x in vs if str(x).strip()]
                     for h, vs in value.items() if str(h).strip()}
        elif key == "strip_env_keys":
            if not isinstance(value, list):
                raise ValueError("strip_env_keys must be a list")
            bad = [k for k in value if not _VAR_NAME_RE.fullmatch(str(k))]
            if bad:
                raise ValueError(f"strip_env_keys: invalid variable name(s) {bad}")
            value = [str(k) for k in value]
        elif isinstance(default, bool):
            if not isinstance(value, bool):
                raise ValueError(f"{key} must be true or false")
        elif isinstance(default, list):
            if not isinstance(value, list):
                raise ValueError(f"{key} must be a list")
            value = [str(x).strip() for x in value if str(x).strip()]
        elif isinstance(default, str):
            value = str(value)
            if key.endswith("_regex"):
                try:
                    re.compile(value)
                except re.error as exc:
                    raise ValueError(f"{key} is not a valid regex: {exc}") from exc
        out[key] = value
    return out


# --------------------------------------------------------------------------- hosts

def _ssh_dest_hosts(text: str) -> list[str]:
    out = []
    for m in _SSH_CMD_RE.finditer(text):
        cmd = m.group(1).lower()
        toks = [t.strip("'\"") for t in m.group(2).split()]
        opts, i = _SSH_ARG_OPTS[cmd], 0
        while i < len(toks):
            tok = toks[i]
            if tok.startswith("-") and len(tok) > 1:
                if tok.startswith("--"):
                    i += 2 if ("=" not in tok and tok in ("--rsh", "--rsync-path", "--port")) else 1
                else:
                    i += 2 if (len(tok) == 2 and tok[1] in opts) else 1
                continue
            if not tok:
                i += 1
                continue
            if cmd == "ssh":
                h = _HOSTTOK_RE.match(tok)
                if h:
                    out.append(h.group(1))
                break  # first positional is the destination; the rest is the remote command
            r = _REMOTE_RE.match(tok)  # scp / sftp / rsync: [user@]host:path operands
            if r:
                out.append(r.group(1))
            elif cmd == "sftp":
                h = _HOSTTOK_RE.match(tok)
                if h:
                    out.append(h.group(1))
                break
            i += 1
    return out


def extract_hosts(text: str) -> list[str]:
    """Destination hosts visible in `text`: URLs, ssh/scp/sftp/rsync targets and nc/telnet hosts."""
    hosts = [m.group(1) for m in _URL_HOST_RE.finditer(text)]
    hosts += _ssh_dest_hosts(text)
    hosts += [m.group(2) for m in _RAW_SOCK_RE.finditer(text)]
    seen, out = set(), []
    for host in hosts:
        host = host.lower().strip("[]")
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def host_matches(host: str, entries) -> bool:
    """True when `host` equals an entry or is a subdomain of a dotted entry."""
    host = host.lower().strip("[]")
    for entry in entries or ():
        entry = str(entry).lower()
        if host == entry or ("." in entry and host.endswith("." + entry)):
            return True
    return False


def rule_for(host: str, rules: dict):
    """Most specific matching host rule as (rule_host, decision), or None."""
    host = host.lower().strip("[]")
    best = None
    for rule_host, decision in (rules or {}).items():
        rh = str(rule_host).lower()
        if host == rh or ("." in rh and host.endswith("." + rh)):
            if best is None or len(rh) > len(best[0]):
                best = (rh, str(decision).lower())
    return best


# --------------------------------------------------------------------------- scanning

def env_refs(text: str, names, name_re: re.Pattern) -> list[str]:
    """Secret-looking variable names referenced in shell, Python or Node syntax."""
    cand = set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", text))
    cand.update(re.findall(r"os\.environ\s*\[\s*['\"]([A-Za-z_]\w*)['\"]", text))
    cand.update(re.findall(r"(?:os\.getenv|os\.environ\.get|getenv)\s*\(\s*['\"]([A-Za-z_]\w*)['\"]", text))
    cand.update(re.findall(r"process\.env\.([A-Za-z_]\w*)", text))
    cand.update(re.findall(r"process\.env\[\s*['\"]([A-Za-z_]\w*)['\"]", text))
    upper = {str(n).upper() for n in names}
    return sorted(c for c in cand if c.upper() in upper or name_re.search(c))


def _compile(pattern: str, fallback: str) -> re.Pattern:
    try:
        return re.compile(pattern, re.I)
    except (re.error, TypeError):
        return re.compile(fallback, re.I)


def scan_text(tool: str, args, cfg: dict) -> str | None:
    """The text egress-guard inspects for this tool call, or None when the tool is not scanned."""
    if not isinstance(args, dict):
        return None
    if tool in cfg["scan_tools_command"]:
        return str(args.get("command") or "")
    if tool in cfg["scan_tools_code"]:
        return str(args.get("code") or "")
    if tool in cfg["scan_tools_url"]:
        return json.dumps(args, default=str)
    return None


def evaluate(tool: str, args, cfg: dict | None = None) -> dict:
    """Scan one tool call.

    Returns {"action": off|log|ask|block, "findings": [...], "hosts": [...], "message": str}.
    The action is the strictest mode among the findings.
    """
    cfg = cfg if cfg is not None else merge_config(None)
    res = {"action": "off", "findings": [], "hosts": [], "message": ""}
    if not cfg.get("enabled"):
        return res
    text = scan_text(tool, args, cfg)
    if not text:
        return res
    if tool in cfg["scan_tools_url"]:
        if not _URL_HOST_RE.search(text):
            return res
    elif not NET_RE.search(text):
        return res  # no network activity: local reads such as `cat .env` are out of scope

    hosts = extract_hosts(text)
    res["hosts"] = hosts
    remote = [h for h in hosts if h not in LOOPBACK]
    rules = cfg.get("host_rules") or {}
    matched = {h: rule_for(h, rules) for h in remote}

    for wanted, mode in (("deny", "block"), ("ask", "ask")):
        hit = next((r for r in matched.values() if r and r[1] == wanted), None)
        if hit:
            res["findings"].append({"type": "host_rule", "detail": f"{wanted} {hit[0]}", "mode": mode})
            res["action"] = mode
            res["message"] = (f"egress-guard: host rule '{wanted}' for {hit[0]} matched in {tool}. "
                              "Do not retry or rephrase this call; ask the user whether it is intended.")
            return res

    allowed = {h for h, r in matched.items() if r and r[1] == "allow"}
    untrusted = [h for h in remote if h not in allowed and not host_matches(h, cfg["trusted_hosts"])]
    unknown_dest = not hosts  # network verb, but the destination is not statically visible ($URL, $(cat host))
    if hosts and not untrusted:
        return res  # every destination is trusted

    allow_map = {h: {str(v).upper() for v in vs} for h, vs in (cfg.get("host_var_allow") or {}).items()}

    def var_allowed(var: str) -> bool:
        if unknown_dest or not untrusted:
            return False
        for dest in untrusted:
            permitted = next((vs for h, vs in allow_map.items() if host_matches(dest, [h])), set())
            if var.upper() not in permitted:
                return False
        return True

    findings = res["findings"]
    names = set(cfg.get("strip_env_keys") or [])
    name_re = _compile(cfg.get("secret_name_regex", ""), DEFAULTS["secret_name_regex"])
    # `export X=...` / `X=val cmd` assignments inside the command define a value; they are not secret reads.
    assigned = set(re.findall(r"(?:^|[;&|\s])(?:export\s+)?([A-Za-z_]\w*)=", text))
    refs = env_refs(text, names, name_re)
    for var in refs:
        if var in assigned and not re.search(r"\$\{?%s\b" % re.escape(var), text):
            continue
        if not var_allowed(var):
            findings.append({"type": "secret_env", "detail": var, "mode": cfg["mode_secret_env"]})

    m = _compile(cfg.get("secret_file_regex", ""), DEFAULTS["secret_file_regex"]).search(text)
    if m:
        findings.append({"type": "secret_file", "detail": m.group(0), "mode": cfg["mode_secret_file"]})

    for rx in LITERAL_SECRET_RES:
        if rx.search(text):
            findings.append({"type": "literal_secret", "detail": rx.pattern[:16] + "...",
                             "mode": cfg["mode_literal_secret"]})
            break

    low = text.lower()
    for term in cfg.get("pii_terms") or []:
        if term and str(term).lower() in low:
            findings.append({"type": "pii", "detail": f"{str(term)[:2]}...({len(str(term))} chars)",
                             "mode": cfg["mode_pii"]})

    if not findings and cfg.get("mode_unknown_host_env", "off") != "off":
        any_refs = sorted(set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", text)) | set(refs))
        any_refs = [r for r in any_refs if not var_allowed(r)]
        if any_refs:
            findings.append({"type": "env_unknown_host", "detail": ",".join(any_refs)[:80],
                             "mode": cfg["mode_unknown_host_env"]})

    findings[:] = [f for f in findings if f["mode"] in LEVELS and f["mode"] != "off"]
    if not findings:
        return res
    order = {lvl: i for i, lvl in enumerate(LEVELS)}
    res["action"] = max((f["mode"] for f in findings), key=lambda lvl: order[lvl])
    dest = ", ".join(untrusted) if untrusted else "an unresolved destination"
    kinds = "; ".join(f"{f['type']}={f['detail']}" for f in findings)
    res["message"] = (f"egress-guard: {tool} would send sensitive data ({kinds}) to {dest}. "
                      "Do not retry or rephrase this call; ask the user whether it is intended.")
    return res


def scrub(text: str, cfg: dict, limit: int = 200) -> str:
    """Short log-safe snippet: literal secrets and pii_terms replaced by placeholders."""
    snippet = str(text)[:limit]
    for rx in LITERAL_SECRET_RES:
        snippet = rx.sub("[SECRET]", snippet)
    for term in cfg.get("pii_terms") or []:
        if term:
            snippet = re.sub(re.escape(str(term)), "[PII]", snippet, flags=re.I)
    return snippet


def unset_prefix(keys) -> str:
    """Shell prefix that unsets `keys` for one command (invalid names are dropped)."""
    valid = [k for k in keys or () if _VAR_NAME_RE.fullmatch(str(k))]
    return f"unset -v {' '.join(valid)} 2>/dev/null; " if valid else ""
