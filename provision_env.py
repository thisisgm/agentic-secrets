#!/usr/bin/env python3
"""Populate a 1Password Environment from op:// references, without leaking values.

Secret values are read locally through a caching `op read` wrapper and handed
straight to the 1Password MCP server over stdio, in-process. This program only
ever prints variable NAMES and ok/fail status, so no secret value reaches a
terminal transcript or an agent's context window.

Run this yourself, from a real terminal. Do not let an agent call the MCP
`append_variables` tool directly: that tool takes the value as an argument, so
an agent-issued call puts the plaintext secret into the model's context. The
whole point of this script is to be the thing that stands between the two.

Usage:
    ./provision_env.py provision            # read refs, push values (the main job)
    ./provision_env.py provision --dry-run  # validate config, read nothing, push nothing
    ./provision_env.py list-environments    # find your environment id
    ./provision_env.py create-environment NAME
    ./provision_env.py list-variables       # names only, never values
    ./provision_env.py mount                # create the local .env mount (a FIFO)

Config: see example.config.toml. Everything account-specific lives there.

CAVEATS (both are properties of 1Password's Environments feature, not of this
script; see the README for the long version):

  1. An Environment stores a literal COPY of each value, not an op:// reference.
     Rotating the vault item does NOT propagate. The Environment goes stale
     until you re-provision or edit it in the 1Password app.

  2. `append_variables` DUPLICATES an existing name instead of updating it, and
     the MCP server exposes no delete tool. When a shell sources the mounted
     .env, the LAST occurrence wins, so a re-run does produce the new value --
     but it leaves dead rows behind. To update in place, edit the value in the
     1Password app instead.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shlex
import subprocess
import sys
import threading
from pathlib import Path

DEFAULT_CONFIG = "config.toml"
DEFAULT_READER = "~/.local/bin/op-cached"
DEFAULT_MCP_COMMAND = ["1password-mcp"]
DEFAULT_TIMEOUT = 120.0

# Values that are obviously still the shipped placeholders.
PLACEHOLDER_MARKERS = ("YOUR_", "CHANGE_ME", "REPLACE_ME", "<", "example-item-id")


class ConfigError(Exception):
    """The config file is missing, malformed, or still full of placeholders."""


class McpError(Exception):
    """The MCP server refused a call, died, or never answered."""


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------


def load_config(path: Path) -> dict:
    if not path.is_file():
        raise ConfigError(
            f"no config at {path}\n"
            f"  copy example.config.toml to {path.name} and fill it in"
        )
    raw = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{path}: invalid JSON: {exc}") from exc
    try:
        import tomllib
    except ModuleNotFoundError as exc:  # Python < 3.11
        raise ConfigError(
            f"{path}: TOML support needs Python 3.11+ (this is "
            f"{sys.version_info.major}.{sys.version_info.minor}); "
            "either upgrade or write the config as JSON and pass --config config.json"
        ) from exc
    try:
        return tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc


def _looks_like_placeholder(value: str) -> bool:
    return any(marker in value for marker in PLACEHOLDER_MARKERS)


def _require(cfg: dict, key: str, path: Path) -> str:
    value = cfg.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{path}: missing required key `{key}`")
    if _looks_like_placeholder(value):
        raise ConfigError(
            f"{path}: `{key}` is still the placeholder ({value!r}). "
            "Fill in your own value -- see the README bootstrap section."
        )
    return value


def resolve_config(path: Path, *, need_env: bool = True, need_vars: bool = False) -> dict:
    cfg = load_config(path)

    out = {
        "account_id": _require(cfg, "account_id", path),
        "environment_id": cfg.get("environment_id", ""),
        "environment_name": cfg.get("environment_name", ""),
        "mount_path": cfg.get("mount_path", ""),
        "reader": os.path.expanduser(cfg.get("reader") or DEFAULT_READER),
        "mcp_command": cfg.get("mcp_command") or list(DEFAULT_MCP_COMMAND),
        "timeout": float(cfg.get("timeout") or DEFAULT_TIMEOUT),
    }

    if isinstance(out["mcp_command"], str):
        out["mcp_command"] = shlex.split(out["mcp_command"])

    if need_env:
        out["environment_id"] = _require(cfg, "environment_id", path)

    variables = cfg.get("variables") or []
    if not isinstance(variables, list):
        raise ConfigError(f"{path}: `variables` must be an array of tables")

    parsed = []
    seen: set[str] = set()
    for i, entry in enumerate(variables):
        if not isinstance(entry, dict):
            raise ConfigError(f"{path}: variables[{i}] must be a table")
        name = entry.get("name")
        ref = entry.get("ref")
        if not name or not ref:
            raise ConfigError(f"{path}: variables[{i}] needs both `name` and `ref`")
        if not str(ref).startswith("op://"):
            raise ConfigError(
                f"{path}: variables[{i}] (`{name}`) ref must start with op:// -- got {ref!r}"
            )
        if _looks_like_placeholder(str(ref)):
            raise ConfigError(
                f"{path}: variables[{i}] (`{name}`) still points at the example ref {ref!r}"
            )
        if name in seen:
            raise ConfigError(
                f"{path}: `{name}` listed twice; the Environment would end up with "
                "duplicate rows (see CAVEAT 2)"
            )
        seen.add(name)
        parsed.append(
            {"name": str(name), "ref": str(ref), "concealed": bool(entry.get("concealed", True))}
        )

    if need_vars and not parsed:
        raise ConfigError(f"{path}: no `[[variables]]` entries to provision")

    out["variables"] = parsed
    return out


# --------------------------------------------------------------------------
# secret reading (values never touch argv, stdout, or this program's logs)
# --------------------------------------------------------------------------


def read_secret(reader: str, ref: str) -> str:
    """Return the secret at `ref`. Never log, never echo, never store the return."""
    if not Path(reader).is_file():
        raise McpError(
            f"secret reader not found: {reader}\n"
            "  install the bundled `op-cached` (see README) or set `reader` in the config"
        )
    if not os.access(reader, os.X_OK):
        raise McpError(f"secret reader is not executable: {reader}\n  chmod +x {reader}")
    try:
        proc = subprocess.run([reader, ref], capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip().splitlines()
        hint = detail[-1] if detail else f"exit {exc.returncode}"
        raise McpError(f"reader failed for {ref}: {hint}") from exc
    value = proc.stdout.rstrip("\n")
    if not value:
        raise McpError(f"reader returned an empty value for {ref}")
    return value


# --------------------------------------------------------------------------
# minimal stdio MCP client
# --------------------------------------------------------------------------


class Mcp:
    def __init__(self, command: list[str], timeout: float = DEFAULT_TIMEOUT):
        self.timeout = timeout
        try:
            self.proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise McpError(
                f"MCP server not found: {command[0]}\n"
                "  install 1Password's Environments MCP server and enable it in the "
                "desktop app, or set `mcp_command` in the config"
            ) from exc
        self._id = 0
        self._q: queue.Queue = queue.Queue()
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._q.put(line)
        self._q.put(None)

    def _write(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
        except BrokenPipeError as exc:
            raise McpError("MCP server closed its stdin (did it crash?)") from exc

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._write(msg)

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        want = self._id
        msg: dict = {"jsonrpc": "2.0", "id": want, "method": method}
        if params is not None:
            msg["params"] = params
        self._write(msg)
        while True:
            try:
                line = self._q.get(timeout=self.timeout)
            except queue.Empty as exc:
                raise McpError(
                    f"MCP server did not answer `{method}` within {self.timeout:.0f}s"
                ) from exc
            if line is None:
                raise McpError(f"MCP server exited while handling `{method}`")
            try:
                resp = json.loads(line)
            except json.JSONDecodeError:
                continue  # server chatter that is not a JSON-RPC frame
            if resp.get("id") == want:
                return resp

    def call(self, tool: str, args: dict) -> str:
        """Call a tool and return its text content. Raises McpError on failure."""
        resp = self.request("tools/call", {"name": tool, "arguments": args})
        if resp.get("error"):
            raise McpError(f"{tool}: {json.dumps(resp['error'])[:400]}")
        result = resp.get("result") or {}
        text = "".join(part.get("text", "") for part in result.get("content", []))
        if result.get("isError"):
            raise McpError(f"{tool}: {text[:400]}")
        return text

    def handshake(self, client_name: str = "provision-env") -> None:
        resp = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": client_name, "version": "1.0"},
            },
        )
        if resp.get("error"):
            raise McpError(f"initialize: {json.dumps(resp['error'])[:400]}")
        self.notify("notifications/initialized")

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def connect(cfg: dict) -> Mcp:
    mcp = Mcp(cfg["mcp_command"], timeout=cfg["timeout"])
    mcp.handshake()
    print("authenticating -- approve the prompt in the 1Password app if it appears", file=sys.stderr)
    mcp.call("authenticate", {})
    return mcp


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_provision(args, cfg: dict) -> int:
    wanted = cfg["variables"]
    if args.only:
        names = set(args.only)
        unknown = names - {v["name"] for v in wanted}
        if unknown:
            raise ConfigError(f"--only names not in config: {', '.join(sorted(unknown))}")
        wanted = [v for v in wanted if v["name"] in names]

    if args.dry_run:
        print(f"dry run: would set {len(wanted)} variable(s) in environment "
              f"{cfg['environment_id']}")
        for v in wanted:
            suffix = f"  <- {v['ref']}" if args.show_refs else ""
            print(f"  {v['name']} (concealed={str(v['concealed']).lower()}){suffix}")
        print("dry run: nothing read from 1Password, nothing written")
        return 0

    # Phase 1: read everything first, so a failing ref does not leave the
    # Environment half-populated.
    payload = []
    for v in wanted:
        payload.append(
            {"name": v["name"], "value": read_secret(cfg["reader"], v["ref"]), "concealed": v["concealed"]}
        )
        print(f"read ok: {v['name']}")

    # Phase 2: hand them to the MCP server in one call.
    mcp = connect(cfg)
    try:
        mcp.call(
            "append_variables",
            {
                "accountId": cfg["account_id"],
                "environmentId": cfg["environment_id"],
                "variables": payload,
            },
        )
    finally:
        mcp.close()
        payload.clear()

    print(f"append ok: {len(wanted)} variable(s)")
    print("note: names already present are now duplicated; last occurrence wins "
          "when the .env is sourced (see CAVEAT 2)")
    return 0


def cmd_list_environments(args, cfg: dict) -> int:
    mcp = connect(cfg)
    try:
        print(mcp.call("list_environments", {"accountId": cfg["account_id"]}))
    finally:
        mcp.close()
    return 0


def cmd_create_environment(args, cfg: dict) -> int:
    mcp = connect(cfg)
    try:
        print(mcp.call(
            "create_environment",
            {"accountId": cfg["account_id"], "environmentName": args.name},
        ))
    finally:
        mcp.close()
    print("copy the new environment id into your config as `environment_id`")
    return 0


def cmd_list_variables(args, cfg: dict) -> int:
    """Names only. The MCP server does not expose values through this tool."""
    mcp = connect(cfg)
    try:
        print(mcp.call(
            "list_variables",
            {"accountId": cfg["account_id"], "environmentId": cfg["environment_id"]},
        ))
    finally:
        mcp.close()
    return 0


def cmd_mount(args, cfg: dict) -> int:
    mount_path = args.path or cfg["mount_path"]
    name = cfg["environment_name"]
    if not mount_path:
        raise ConfigError("no mount path: set `mount_path` in the config or pass --path")
    if not name:
        raise ConfigError("no environment name: set `environment_name` in the config")
    mount_path = os.path.expanduser(mount_path)
    parent = Path(mount_path).parent

    if args.dry_run:
        print(f"dry run: would mount environment {name} at {mount_path}")
        return 0

    parent.mkdir(parents=True, exist_ok=True)
    os.chmod(parent, 0o700)

    mcp = connect(cfg)
    try:
        print(mcp.call(
            "create_local_env_file",
            {
                "accountId": cfg["account_id"],
                "environmentId": cfg["environment_id"],
                "environmentName": name,
                "mountPath": mount_path,
            },
        ))
    finally:
        mcp.close()

    print(f"mounted at {mount_path}")
    print(f"verify it is a FIFO:  ls -l {shlex.quote(mount_path)}   # expect a leading 'p'")
    return 0


def cmd_list_mounts(args, cfg: dict) -> int:
    mcp = connect(cfg)
    try:
        print(mcp.call(
            "list_local_env_files",
            {"accountId": cfg["account_id"], "environmentId": cfg["environment_id"]},
        ))
    finally:
        mcp.close()
    return 0


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="provision_env.py",
        description="Populate a 1Password Environment from op:// refs without "
                    "printing any secret value.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run from a real terminal. Never let an agent call the MCP "
               "append_variables tool directly -- that puts plaintext in its context.",
    )
    p.add_argument("--config", default=DEFAULT_CONFIG, type=Path,
                   help=f"config file, .toml or .json (default: {DEFAULT_CONFIG})")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("provision", help="read op:// refs and push values into the Environment")
    sp.add_argument("--dry-run", action="store_true",
                    help="validate config and print the plan; read and write nothing")
    sp.add_argument("--only", action="append", metavar="NAME",
                    help="provision just this variable (repeatable)")
    sp.add_argument("--show-refs", action="store_true",
                    help="include op:// references in --dry-run output")
    sp.set_defaults(func=cmd_provision, need_env=True, need_vars=True)

    sp = sub.add_parser("list-environments", help="list Environments in the account (names + ids)")
    sp.set_defaults(func=cmd_list_environments, need_env=False, need_vars=False)

    sp = sub.add_parser("create-environment", help="create a new Environment and print its id")
    sp.add_argument("name")
    sp.set_defaults(func=cmd_create_environment, need_env=False, need_vars=False)

    sp = sub.add_parser("list-variables", help="list variable NAMES in the Environment (no values)")
    sp.set_defaults(func=cmd_list_variables, need_env=True, need_vars=False)

    sp = sub.add_parser("mount", help="create the local .env mount (a named pipe)")
    sp.add_argument("--path", help="override `mount_path` from the config")
    sp.add_argument("--dry-run", action="store_true", help="print what would be mounted")
    sp.set_defaults(func=cmd_mount, need_env=True, need_vars=False)

    sp = sub.add_parser("list-mounts", help="list local .env mounts for the Environment")
    sp.set_defaults(func=cmd_list_mounts, need_env=True, need_vars=False)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        cfg = resolve_config(args.config, need_env=args.need_env, need_vars=args.need_vars)
        return args.func(args, cfg)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except McpError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
