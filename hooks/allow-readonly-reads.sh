#!/bin/bash
# allow-readonly-reads — PreToolUse(Bash): approve genuinely read-only commands
# so a leading `cd` stops stalling agent sessions on a permission prompt.
#
# WHY THIS EXISTS
# Six times on 2026-09-05, sessions stalled on prompts of the form:
#   "grep on 'src/x.ts' after a cd would search a directory that cannot be
#    determined here, and a Read() deny rule is configured"
# The commands were harmless greps every time. The escalation is not about the
# command — it is that a leading `cd` makes later relative paths unresolvable to
# static inspection, so the deny rules cannot be cleared. Two of the six came
# from subagent-authored commands, which no amount of instructing the parent
# session can fix. PreToolUse hooks DO fire inside subagents, so this reaches
# them.
#
# DESIGN: allowlist, not denylist. A command is approved only if EVERY segment
# starts with a known read-only binary AND the whole string trips none of the
# hard rejects. Anything else prints nothing and exits 0, which is explicitly
# "no decision" — the normal permission flow still runs. This hook can only ever
# turn a prompt into an approval; it can never turn an approval into a denial,
# and it never speaks unless it is certain.
#
# THE ONE RULE THAT MUST NOT ROT: an "allow" here outranks the settings.json
# deny rules, so the secret-path rejects below are load-bearing. Never add a
# command to ALLOW that can write, execute, fetch, or interpret.
#
# Audit trail: every approval is logged. Read it.
set -uo pipefail

LOG="${XDG_STATE_HOME:-$HOME/.local/state}/claude-hooks/allow-readonly-reads.log"
mkdir -p "$(dirname "$LOG")" 2>/dev/null

IN=$(cat)
CMD=$(printf '%s' "$IN" | jq -r '.tool_input.command // empty' 2>/dev/null)
CWD=$(printf '%s' "$IN" | jq -r '.cwd // empty' 2>/dev/null)
AGENT=$(printf '%s' "$IN" | jq -r '.agent_id // "main"' 2>/dev/null)

[ -n "$CMD" ] || exit 0

decline() { exit 0; }   # silence = no decision, normal permission flow

# ---- hard rejects, checked against the whole command string ----------------
# Anything that could write, execute, fetch, interpret, or reach a secret.
# A background `&` is rejected; `&&` is fine. Kept out of the case below
# because a bare & in a case pattern is a bash syntax error — and a syntax
# error exits 2, which BLOCKS the tool call. This hook must never exit 2.
if printf '%s' "$CMD" | grep -qE '(^|[^&])&([^&]|$)'; then decline; fi

# Secret-path matching is done on a lowercased copy: `grep TOKEN config.json`
# slipped through a case-sensitive check during testing.
LOW=$(printf '%s' "$CMD" | tr '[:upper:]' '[:lower:]')

case "$CMD" in
  *'$('*|*'`'*|*'>'*|*'<'*|*'${'*)                                 decline ;;
esac
case "$LOW" in
  *.env*|*secrets*|*secret*|*.ssh*|*id_rsa*|*.netrc*|*.aws*)       decline ;;
  *credential*|*token*|*password*|*passwd*|*keychain*|*apikey*)    decline ;;
  *api_key*|*private_key*|*.pem*|*.p12*|*.gpg*|*.age*)             decline ;;
esac
# Dangerous FLAGS only. Command names are NOT checked by substring here — the
# per-segment allowlist below is the real gate, and substring matching on short
# names is actively wrong: `*ln *` matched the flag `-rln `, silently killing
# every recursive grep. Same trap waits in rm/mv/cp/dd inside ordinary words.
case "$CMD" in
  *-exec*|*-execdir*|*-delete*|*-ok\ *)                            decline ;;
  *sed\ -i*|*--in-place*|*sort\ -o*)                               decline ;;
esac

# ---- allowlist: every segment's first word must be read-only ---------------
ALLOW=" cd grep egrep fgrep rg sed ls cat head tail wc sort uniq cut tr echo printf find jq file stat basename dirname realpath pwd true test date "

# Split on && || ; | and newlines, then check each segment's leading word.
#
# Pure bash on purpose. The first version used `sed 's/&&/\036/g'`, which is a
# GNU-ism: BSD sed does not read \036 as an octal escape, so on macOS the split
# never happened, every command collapsed to ONE segment, and `cd /x && rm -rf
# build` was judged on the word `cd` alone and approved. The substring rejects
# were hiding it. Parameter expansion has no such portability trap.
SEGS="${CMD//&&/$'\n'}"
SEGS="${SEGS//||/$'\n'}"
SEGS="${SEGS//;/$'\n'}"
SEGS="${SEGS//|/$'\n'}"
while IFS= read -r seg; do
  # strip leading whitespace and any VAR=value prefixes
  seg="${seg#"${seg%%[![:space:]]*}"}"
  while [[ "$seg" =~ ^[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+ ]]; do
    seg="${seg#*[[:space:]]}"
    seg="${seg#"${seg%%[![:space:]]*}"}"
  done
  [ -n "$seg" ] || continue
  word="${seg%%[[:space:]]*}"
  word="${word##*/}"                       # allow /usr/bin/grep
  case "$ALLOW" in *" $word "*) ;; *) decline ;; esac
done <<< "$SEGS"

# ---- approve ---------------------------------------------------------------
printf '%s %s agent=%s cwd=%s :: %s\n' \
  "$(date -u +%FT%TZ)" ALLOW "$AGENT" "$CWD" "$CMD" >> "$LOG" 2>/dev/null

jq -n --arg r "Read-only command (allowlisted binaries, no writes, redirection, substitution, network or secret paths). Approved by allow-readonly-reads so a leading cd does not stall the session." '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "allow",
    permissionDecisionReason: $r
  }
}'
