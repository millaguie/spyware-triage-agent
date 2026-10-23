#!/usr/bin/env bash
# Start the pi agent that guides a phone check.
# The phone data stays on this machine: use a model on the local network only.
set -euo pipefail
DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$DIR"

PROVIDER="${STA_PROVIDER:-llm}"
MODEL="${STA_MODEL:-qwen3.8-27b}"

./sta doctor >/dev/null || { echo "Run ./install.sh (or ./install.sh --docker) first."; exit 1; }

# Only read and bash: the agent must not edit findings or the report by hand.
# A free shell is not a security boundary: OPERATOR.md and the terminal checks
# in ./sta stop mistakes, not a determined prompt injection. The MCP mode in
# docs/plan-wizard.md (no shell at all) replaces this script.
# No context files and no skills: the operator prompt is the whole instruction set.
exec pi --provider "$PROVIDER" --model "$MODEL" \
  --tools read,bash --no-context-files --no-skills --no-extensions \
  --system-prompt "$(cat agent/OPERATOR.md)" \
  "${@:-Hello. I want to check a phone.}"
