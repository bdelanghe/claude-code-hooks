#!/usr/bin/env bash
# PreToolUse(Bash) hook: run known-slow commands with run_in_background so the
# session is not blocked waiting on them. Whitelisted commands only; every
# other command passes through untouched. NEVER blocks — any error path is a
# no-op (exit 0, no JSON), so the original command runs unchanged.
#
# Tradeoff: backgrounded output does NOT come back inline. It goes to a file
# and the session has to call TaskOutput (or Read the path) to see it. A `make`
# that finishes in two seconds becomes a two-step round trip. The whitelist is
# deliberately short for that reason — add a command here only if waiting on it
# is routinely worse than fetching its output separately.
#
# Placement: nix owns this script, which reaches PATH as
# `claude-hook-auto-background-bash` (this repo's Home Manager module). settings.json
# keeps only a one-line registration by that stable name. The wiring is still a
# hand edit, and still survives `home-manager switch`, because the
# claude-token-tools flake's activation patch merges only scalars and env into
# settings.json and never touches `hooks`.

input=$(cat 2>/dev/null) || exit 0
cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[ -z "$cmd" ] && exit 0

# Already backgrounded by the caller — nothing to do.
bg=$(printf '%s' "$input" | jq -r '.tool_input.run_in_background // false' 2>/dev/null) || exit 0
[ "$bg" = "true" ] && exit 0

# Hard exclusion: anything cap-verbose-bash.sh rewrites. Two PreToolUse hooks
# both returning updatedInput for one command would fight, and cap-verbose's
# wrapper buffers to a temp file and tails it at the end, which defeats
# backgrounding anyway. cap-verbose owns `bun test` / `bun run test`.
# Keep this alternation in sync with cap-verbose-bash.sh.
if printf '%s' "$cmd" | grep -Eq '(^| )(bun run verify|bun run regen|bun( run)? test|bun run cli validate|bun run harness/validate_|git status)'; then
  exit 0
fi

# Only background these known-slow commands. Extend the alternation as needed.
#
# The command must sit in *command position* — start of string or after a shell
# separator (; && || |), with optional VAR=value prefixes — not merely after a
# space. Otherwise `echo make believe` backgrounds itself. `cmake` must not
# match `make`, and `cd foo && make` must.
if ! printf '%s' "$cmd" | grep -Eq '(^|[;&|(]+)[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)*(cargo (build|test)|npm test|npm run build|pytest|make)([[:space:]]|$)'; then
  exit 0
fi

# Merge, do not replace. The docs are explicit that updatedInput "Replaces the
# entire input object, so include unchanged fields alongside modified ones" —
# tool_input carries description/timeout next to command, and returning
# {command} alone would drop them.
#
# Deliberately NO permissionDecision. "allow" would skip the permission prompt
# for every command this hook matches, which is a permission change nobody
# asked for; it is only *required* alongside updatedInput for AskUserQuestion
# and ExitPlanMode. Omitting it leaves the normal permission flow intact and
# still applies the rewrite.
jq -nc --argjson inp "$input" \
  '{hookSpecificOutput:{hookEventName:"PreToolUse",updatedInput:($inp.tool_input + {run_in_background:true})}}' \
  2>/dev/null || exit 0
exit 0
