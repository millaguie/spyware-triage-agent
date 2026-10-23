"""MCP server for the agent: the sta steps as tools.

MCP (Model Context Protocol) lets pi, opencode and Claude Code call outside
tools. This is the protocol's minimum, written by hand: JSON-RPC, one message
per line on stdin and stdout. No SDK, so no new dependency.

stdin and stdout belong to the protocol. Nothing here may print to stdout or
read stdin for any other reason, and the server never asks the operator
anything: consent and passwords are asked in the operator's own terminal.

Spike version: one tool, `next_step`. The full tool set comes in phase 3
(docs/plan-wizard.md)."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Newest first. We answer with the client's version only when we know it.
PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"]
TIMEOUT = 60  # seconds; next_step only reads the case state

TOOLS = [
    {"name": "next_step",
     "description": "Tells you what to say to the user and which tool to call next.",
     "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False}},
]


def sta(*args: str) -> tuple[str, bool]:
    """Output of ./sta, and whether it failed. stdin is closed: a command
    that wants to ask the operator something fails instead of waiting."""
    try:
        proc = subprocess.run([str(ROOT / "sta"), *args], cwd=ROOT, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return f"The check did not answer in {TIMEOUT} seconds. Tell the user to wait, then call next_step.", True
    if proc.returncode != 0:
        return proc.stderr.strip() or proc.stdout.strip() or f"Failed with exit code {proc.returncode}.", True
    return proc.stdout.strip(), False


def call(name: str) -> tuple[str, bool]:
    if name == "next_step":
        return sta("next")
    return f"Unknown tool {name}. Call next_step.", True


def handle(msg) -> dict | None:
    if not isinstance(msg, dict):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "not a request"}}
    method, mid = msg.get("method"), msg.get("id")
    if mid is None or method is None:
        return None  # a notification, or a client's answer to a request we never send
    if method == "initialize":
        asked = (msg.get("params") or {}).get("protocolVersion")
        result = {"protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "sta", "version": "0.1"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        text, error = call((msg.get("params") or {}).get("name", ""))
        result = {"content": [{"type": "text", "text": text}], "isError": error}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"no method {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            reply = handle(json.loads(line))
        except json.JSONDecodeError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "bad JSON"}}
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
