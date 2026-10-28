#!/usr/bin/env bash
# Goldens + mutation test for hooks/no-adhoc-notifications.sh (PreToolUse(Bash): deny an agent's hand-raised macOS banner).
# Allowed examples print NOTHING and exit 0; denied examples print a deny decision citing the rule and exit 0. MUTATION: with the osascript case disabled in a copy, the osascript goldens must
# FAIL (proves they bite). Also: parse problems fail open; the shared registrar adds this hook by its own name, once, next to the no-bypass hook.
# NOT covered: a real Claude Code session, obfuscated commands (the script says it does not stop them). Run: bash tests/no-adhoc-notifications-hook.sh. Needs jq.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; HOOK="$HERE/../hooks/no-adhoc-notifications.sh"; REG="$HERE/../hooks/register-no-bypass-hook.sh"
command -v jq >/dev/null 2>&1 || { echo "FAIL: jq is required"; exit 1; }
fail=0; ok() { if [ "$2" = 1 ]; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
T=$(mktemp -d "${TMPDIR:-/tmp}/no-notif.XXXXXX") || exit 1; trap 'rm -rf "$T"' EXIT
run() { OUT=$(jq -cn --arg c "$2" '{tool_name:"Bash",tool_input:{command:$c}}' | bash "$1" 2>/dev/null); RC=$?; }
denied() { [ "$RC" = 0 ] && printf '%s' "$OUT" | jq -e '.hookSpecificOutput.permissionDecision == "deny" and (.hookSpecificOutput.permissionDecisionReason | contains("No ad-hoc desktop notifications"))' >/dev/null 2>&1; }
allowed() { [ "$RC" = 0 ] && [ -z "$OUT" ]; }

ALLOW=(
  "osascript -e 'tell application \"Finder\" to get name of front window'"
  "osascript -e 'display dialog \"Touch ID?\" buttons {\"OK\"}'"
  'echo "never run osascript display notification"'
  'git commit -m "hook: deny osascript display notification and terminal-notifier"'
  'grep -rn "display notification" programs/'
  'chitin notify fleet-repair --body "seat exited" --severity attention'
  'ls -la'
)
DENY=(
  "osa:osascript -e 'display notification \"Approve the chitin signing prompt\" with title \"Claude Code\"' 2>/dev/null; echo done"
  "osa:osascript -e 'display notification \"done\"'"
  "osa:/usr/bin/osascript -e 'display  notification \"x\"'"
  "osa:cd /tmp && osascript -e 'display notification \"x\"'"
  "osa:bash -c 'osascript -e \"display notification \\\"x\\\"\"'"
  "osa:echo hi | osascript -e 'display notification \"x\"'"
  'tn:terminal-notifier -title Claude -message done'
  'tn:alerter -message hi'
)
for c in "${ALLOW[@]}"; do run "$HOOK" "$c"; ok "allowed: $c" "$(allowed && echo 1 || echo 0)"; done
for e in "${DENY[@]}"; do c=${e#*:}; run "$HOOK" "$c"; ok "denied: $c" "$(denied && echo 1 || echo 0)"; done

# mutation: disable the osascript case; every osascript golden must stop being denied
sed 's/^    osascript) /    osascript_DISABLED) /' "$HOOK" >"$T/mut.sh"
bit=1; for e in "${DENY[@]}"; do [ "${e%%:*}" = osa ] || continue; run "$T/mut.sh" "${e#*:}"; denied && bit=0; done
ok "mutation: with the osascript case disabled, no osascript golden is denied (the goldens bite)" "$bit"

# fail open
OUT=$(printf 'not json' | bash "$HOOK" 2>/dev/null); RC=$?; ok "invalid input: no output, exit 0" "$( [ "$RC" = 0 ] && [ -z "$OUT" ] && echo 1 || echo 0 )"
OUT=$(printf '{"tool_input":{}}' | bash "$HOOK" 2>/dev/null); RC=$?; ok "no command: no output, exit 0" "$( [ "$RC" = 0 ] && [ -z "$OUT" ] && echo 1 || echo 0 )"

# registration: the shared registrar adds this hook by its own name, once, alongside an existing no-bypass entry
printf '%s\n' '{"model":"x","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/h/.nix-profile/bin/claude-hook-no-bypass-macos-blocks 2>/dev/null || true"}]}]}}' >"$T/s.json"
HOOK_CMD=/h/.nix-profile/bin/claude-hook-no-adhoc-notifications bash "$REG" "$T/s.json"
HOOK_CMD=/h/.nix-profile/bin/claude-hook-no-adhoc-notifications bash "$REG" "$T/s.json"
ok "registered once, next to no-bypass, other keys kept" "$( jq -e '.model == "x" and ([.hooks.PreToolUse[].hooks[].command] | (map(select(contains("claude-hook-no-adhoc-notifications"))) | length) == 1) and ([.hooks.PreToolUse[].hooks[].command] | any(contains("claude-hook-no-bypass-macos-blocks")))' "$T/s.json" >/dev/null && echo 1 || echo 0 )"
NOBYPASS_CMD=/h/.nix-profile/bin/claude-hook-no-bypass-macos-blocks bash "$REG" "$T/s.json"
ok "the no-bypass registration is still idempotent (its name already present)" "$( [ "$(jq '[.hooks.PreToolUse[].hooks[].command | select(contains("no-bypass"))] | length' "$T/s.json")" = 1 ] && echo 1 || echo 0 )"

[ "$fail" = 0 ] && echo "all ok" || { echo "FAILURES"; exit 1; }
