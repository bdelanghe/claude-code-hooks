#!/bin/bash
# register-no-bypass-hook.sh <settings.json>...: add the PreToolUse(Bash) guard `claude-hook-no-bypass-macos-blocks` to each Claude settings file's hooks, ONLY IF no PreToolUse entry already names it.
# Run by the home switch (the Home Manager module, home.activation). Additive: settings.json is state Claude Code writes at runtime,
# so it is never declared as a read-only store file; a switch only MERGES an entry in.
#   - a file that does not exist is NOT created; a symlink, a non-regular file, or something that is not a JSON object is left byte for byte (a note on stderr);
#   - existing PreToolUse hooks and every other key are preserved; the entry is appended once (idempotent);
#   - written through a temp file next to the target and an atomic rename; the file mode is kept.
# The command is registered by ABSOLUTE path with `2>/dev/null || true` (env NOBYPASS_CMD; default $HOME/.nix-profile/bin/claude-hook-no-bypass-macos-blocks): a hook that exits 2 blocks the tool call, so a
# broken script must not freeze every Bash call; the deny is a JSON decision on stdout with exit 0, which `|| true` does not disturb. A relative command path is refused.
# Always exits 0 (a switch must not fail on a settings file). Env: JQ (default jq).
set -u
JQ=${JQ:-jq}
# HOOK_CMD registers another PreToolUse(Bash) guard the same way (claude-hook-no-adhoc-notifications, 2026-10-27); the "already registered" check is by the command's basename.
CMD=${HOOK_CMD:-${NOBYPASS_CMD:-${HOME:-}/.nix-profile/bin/claude-hook-no-bypass-macos-blocks}}
NAME=${CMD##*/}
case "$CMD" in /*) ;; *) echo "register-no-bypass-hook: the command path is not absolute ($CMD); nothing written" >&2; exit 0;; esac
ENTRY=$("$JQ" -cn --arg c "$CMD 2>/dev/null || true" '{matcher: "Bash", hooks: [{type: "command", command: $c}]}' 2>/dev/null) || { echo "register-no-bypass-hook: jq not usable; nothing written" >&2; exit 0; }
for f in "$@"; do
  if [ -L "$f" ]; then echo "register-no-bypass-hook: $f is a symlink; left alone" >&2; continue; fi
  [ -e "$f" ] || continue
  if [ ! -f "$f" ]; then echo "register-no-bypass-hook: $f is not a regular file; left alone" >&2; continue; fi
  if ! "$JQ" -e 'type == "object"' "$f" >/dev/null 2>&1; then echo "register-no-bypass-hook: $f is not a JSON object; left alone" >&2; continue; fi
  if "$JQ" -e --arg n "$NAME" '[(.hooks.PreToolUse // [])[]? | .hooks[]? | .command // ""] | any(contains($n))' "$f" >/dev/null 2>&1; then continue; fi
  mode=$(/usr/bin/stat -f %Lp "$f" 2>/dev/null || stat -c %a "$f" 2>/dev/null)
  tmp=$(mktemp "$f.XXXXXX") || { echo "register-no-bypass-hook: no temp file next to $f; left alone" >&2; continue; }
  if "$JQ" --argjson e "$ENTRY" '.hooks = ((.hooks // {}) | .PreToolUse = ((.PreToolUse // []) + [$e]))' "$f" >"$tmp" 2>/dev/null && [ -s "$tmp" ]; then
    [ -z "$mode" ] || chmod "$mode" "$tmp" 2>/dev/null
    mv -f "$tmp" "$f"
  else
    rm -f "$tmp"; echo "register-no-bypass-hook: could not merge into $f; left alone" >&2
  fi
done
exit 0
