#!/usr/bin/env bash
# Goldens + mutation test for hooks/no-bypass-macos-blocks.sh (the PreToolUse(Bash) guard from the 2026-10-20 incident: codesign --force -s - on a revoked-cert binary).
# For each rule family: allowed examples (must print NOTHING, exit 0) and denied examples (must print a deny decision citing the rule, exit 0). MUTATION: with one family's case label disabled in a
# copy of the script, that family's denied goldens must FAIL (proves the goldens bite). Also: parse problems fail open; the registration script is additive and idempotent.
# NOT covered: a real Claude Code session, the real macOS tools, obfuscated commands (the script says it does not stop them). Run: bash tests/no-bypass-hook.sh. Needs jq.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; HOOK="$HERE/../hooks/no-bypass-macos-blocks.sh"; REG="$HERE/../hooks/register-no-bypass-hook.sh"
command -v jq >/dev/null 2>&1 || { echo "FAIL: jq is required"; exit 1; }
fail=0; ok() { if [ "$2" = 1 ]; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
T=$(mktemp -d "${TMPDIR:-/tmp}/no-bypass.XXXXXX") || exit 1; trap 'rm -rf "$T"' EXIT
run() { # SCRIPT COMMAND -> OUT, RC
  OUT=$(jq -cn --arg c "$2" '{tool_name:"Bash",tool_input:{command:$c}}' | bash "$1" 2>/dev/null); RC=$?
}
denied() { [ "$RC" = 0 ] && printf '%s' "$OUT" | jq -e '.hookSpecificOutput.permissionDecision == "deny" and .hookSpecificOutput.hookEventName == "PreToolUse" and (.hookSpecificOutput.permissionDecisionReason | contains("Never bypass a macOS block"))' >/dev/null 2>&1; }
allowed() { [ "$RC" = 0 ] && [ -z "$OUT" ]; }

ALLOW=(
  'codesign:codesign -dv --verbose=4 /Applications/Foo.app'
  'codesign:codesign --verify --deep --strict /Applications/Foo.app'
  'xattr:xattr -l /tmp/file'
  'xattr:xattr -p com.apple.quarantine /tmp/file'
  'spctl:spctl --assess --verbose /Applications/Foo.app'
  'spctl:spctl --status'
  'agent:npm view @openai/codex versions'
  'agent:npm install lodash'
  'agent:bun add zod'
  'agent:pip install requests'
  'misc:echo "bun install @openai/codex@0.128.0 then codesign -s - x"'
  'misc:git commit -m "document: codesign --force and xattr -d are denied"'
  'misc:grep -rn "spctl --master-disable" docs/'
  'misc:ls -la'
)
DENY=(
  'codesign:codesign --force -s - ./cx/codex'
  'codesign:codesign -fs - ./cx/codex'
  'codesign:codesign --remove-signature ./bin/x'
  'codesign:sudo codesign --sign - /tmp/x'
  'codesign:cd /tmp/cx && codesign --force --sign - codex'
  'xattr:xattr -d com.apple.quarantine /tmp/x'
  'xattr:xattr -cr /Users/u/Downloads/x.app'
  'xattr:xattr -dr com.apple.quarantine ~/x'
  'spctl:spctl --add /tmp/x'
  'spctl:sudo spctl --master-disable'
  'spctl:spctl --global-disable'
  'agent:bun install @openai/codex@0.128.0'
  'agent:npm i -g @anthropic-ai/claude-code'
  'agent:npx @google/gemini-cli'
  'agent:pip install aider-chat'
  'agent:bunx opencode-ai'
  'agent:cd /tmp && bun add @openai/codex'
  'wrapped:bash -c "codesign --force -s - x"'
  "wrapped:sh -c 'xattr -cr y'"
  'wrapped:echo x | xargs codesign -s - y'
  'wrapped:X=$(codesign -s - y)'
  'wrapped:FOO=1 spctl --add z'
)
for e in "${ALLOW[@]}"; do fam=${e%%:*}; c=${e#*:}; run "$HOOK" "$c"; ok "allow [$fam] $c" $( allowed && echo 1 || echo 0 ); done
for e in "${DENY[@]}"; do fam=${e%%:*}; c=${e#*:}; run "$HOOK" "$c"; ok "DENY  [$fam] $c" $( denied && echo 1 || echo 0 ); done

# fail open
OUT=$(printf 'not json' | bash "$HOOK" 2>/dev/null); RC=$?; ok "garbage input: exit 0, no output (fail open)" $( [ "$RC" = 0 ] && [ -z "$OUT" ] && echo 1 || echo 0 )
OUT=$(jq -cn '{tool_name:"Bash",tool_input:{}}' | bash "$HOOK" 2>/dev/null); RC=$?; ok "no command: exit 0, no output" $( [ "$RC" = 0 ] && [ -z "$OUT" ] && echo 1 || echo 0 )
ok "the script parses under macOS /bin/bash 3.2 and under the default bash" $( /bin/bash -n "$HOOK" && bash -n "$HOOK" && echo 1 || echo 0 )
ok "no here-document / here-string in the hook (portable and sandbox-friendly)" $( grep -vE '^[[:space:]]*#' "$HOOK" | grep -qE '<<<|<<-?[[:space:]]*["'"'"']?[A-Za-z_]' && echo 0 || echo 1 )

# mutation: disable one family at a time; its denied goldens must fail
src=$(cat "$HOOK")
mutate() { # LABEL-TEXT REPLACEMENT -> $T/mut.sh
  printf '%s\n' "${src/"$1"/"$2"}" >"$T/mut.sh"; cmp -s "$HOOK" "$T/mut.sh" && return 1; return 0
}
for fam in codesign xattr spctl agent; do
  case "$fam" in
    codesign) old='    codesign)'; new='    codesignOFF)';;
    xattr)    old='    xattr)';    new='    xattrOFF)';;
    spctl)    old='    spctl)';    new='    spctlOFF)';;
    agent)    old='    npm|pnpm|yarn|bun|bunx|npx|pnpx|pip|pip3|pipx|uv|uvx|cargo)'; new='    npmOFF)';;
  esac
  if ! mutate "$old" "$new"; then ok "MUTATION [$fam]: the mutation point was found in the script" 0; continue; fi
  caught=0
  for e in "${DENY[@]}"; do [ "${e%%:*}" = "$fam" ] || continue; run "$T/mut.sh" "${e#*:}"; denied || caught=$((caught + 1)); done
  want=0; for e in "${DENY[@]}"; do [ "${e%%:*}" = "$fam" ] && want=$((want + 1)); done
  ok "MUTATION [$fam]: with the $fam rule disabled all $want of its denied goldens FAIL (caught $caught)" $( [ "$caught" = "$want" ] && [ "$want" -gt 0 ] && echo 1 || echo 0 )
done

# registration script: additive, idempotent, never touches other hooks, leaves odd files alone
S1="$T/settings.json"; CMD=/abs/bin/claude-hook-no-bypass-macos-blocks
jq -n '{model:"x", hooks:{PreToolUse:[{matcher:"Bash",hooks:[{type:"command",command:"other-hook"}]}], Stop:[{hooks:[{type:"command",command:"s"}]}]}}' >"$S1"
chmod 640 "$S1"
NOBYPASS_CMD="$CMD" bash "$REG" "$S1" "$T/missing.json"; r1=$(cat "$S1")
ok "register: adds ONE PreToolUse Bash entry naming the guard (with || true), keeps the other PreToolUse hook, Stop hook and model" \
  $( printf '%s' "$r1" | jq -e --arg c "$CMD" '.model == "x" and .hooks.Stop[0].hooks[0].command == "s" and ([.hooks.PreToolUse[].hooks[].command] | length == 2) and ([.hooks.PreToolUse[].hooks[].command] | any(. == "other-hook")) and ([.hooks.PreToolUse[].hooks[].command] | any(contains($c) and endswith("|| true")))' >/dev/null && echo 1 || echo 0 )
NOBYPASS_CMD="$CMD" bash "$REG" "$S1"; ok "register: idempotent (a second run changes nothing)" $( [ "$(cat "$S1")" = "$r1" ] && echo 1 || echo 0 )
ok "register: the file mode is kept (640) and a missing file is not created" $( [ "$(/usr/bin/stat -f %Lp "$S1")" = 640 ] && [ ! -e "$T/missing.json" ] && echo 1 || echo 0 )
printf 'not json' >"$T/bad.json"; NOBYPASS_CMD="$CMD" bash "$REG" "$T/bad.json" 2>/dev/null; ok "register: an invalid JSON file is left byte for byte" $( [ "$(cat "$T/bad.json")" = "not json" ] && echo 1 || echo 0 )
ln -s "$S1" "$T/link.json"; before=$(cat "$S1"); NOBYPASS_CMD="$CMD" bash "$REG" "$T/link.json" 2>/dev/null; ok "register: a symlink is left alone" $( [ -L "$T/link.json" ] && [ "$(cat "$S1")" = "$before" ] && echo 1 || echo 0 )
jq -n '{hooks:{}}' >"$T/nohook.json"; NOBYPASS_CMD="$CMD" bash "$REG" "$T/nohook.json"; ok "register: works when there is no PreToolUse yet" $( jq -e '.hooks.PreToolUse | length == 1' "$T/nohook.json" >/dev/null && echo 1 || echo 0 )
jq -n '{model:"y"}' >"$T/nohooks-key.json"; NOBYPASS_CMD="$CMD" bash "$REG" "$T/nohooks-key.json"; ok "register: works when there is no hooks key at all" $( jq -e '.model == "y" and (.hooks.PreToolUse | length == 1)' "$T/nohooks-key.json" >/dev/null && echo 1 || echo 0 )
NOBYPASS_CMD="relative/path" bash "$REG" "$T/nohook.json" 2>/dev/null; ok "register: a relative command path is refused (nothing written)" $( jq -e '.hooks.PreToolUse | length == 1' "$T/nohook.json" >/dev/null && echo 1 || echo 0 )
[ "$fail" = 0 ] && echo "all ok" || { echo "FAILURES"; exit 1; }
