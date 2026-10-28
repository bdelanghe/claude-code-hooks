#!/usr/bin/env bash
# PreToolUse(Bash) hook: DENY the commands that bypass a macOS block or install agent CLIs ad hoc (rule "Never bypass a macOS block").
# INCIDENT: a research subagent ran `bun install @openai/codex@0.128.0` onto the host and executed the vendored binary; macOS blocked it ("Malware Blocked", certificate revoked,
# CSSMERR_TP_CERT_REVOKED); the agent then ran `codesign --force -s -` to re-sign it ad hoc and ran it again. That defeats the protection meant for a possibly-compromised signing key.
#
# WHAT IT DENIES (a command, or any segment of a pipeline / `;` / `&&` list, or the body of `bash -c '...'`, whose command word is):
#   codesign   with --force / -f, with a signing flag (-s / --sign, incl. `-s -`), or with --remove-signature   (display and verify are allowed: -d, -dv, -v, --verify, -R)
#   xattr      with a delete or clear flag (-d, -c, -dr, -cr ...)   (listing, reading and writing are allowed: -l, -p, -w)
#   spctl      with --add, --remove, --enable, --disable, --master-disable, --global-disable, --global-enable   (--assess / -a and --status are allowed)
#   npm | pnpm | yarn | bun | bunx | npx | pnpx | pip | pip3 | pipx | uv | uvx | cargo  that names an AGENT CLI package (@openai/codex, @anthropic-ai/claude-code,
#     @google/gemini-cli, opencode-ai, cursor-agent, ...) unless the verb only reads metadata (view, info, show, search, outdated, docs)
# Everything else prints nothing and exits 0 ("no decision": the normal permission flow runs). It can only turn an allow into a deny for these commands.
#
# HONEST LIMITS. This is a regex over a command STRING, not endpoint security. It stops an honest agent that reaches for the wrong tool (the incident), and it puts the rule in front of the model
# in the denial text. It does NOT stop a determined one: `eval`, variable concatenation, a script file written first and run later, a different language (python -c ... subprocess), or a
# binary renamed before the call all pass. The real barrier is binary authorization (Santa) or running third-party code only in a VM/Seatbelt sandbox; not this hook.
#
# FAILS OPEN on a parse problem (no jq output, empty command): the registration line has `|| true` as every hook here does, because a hook that exits 2 BLOCKS the tool call.
# Bash 3.2 safe (no mapfile, no associative arrays). Never reads or prints anything but the command it was given.
input=$(cat 2>/dev/null) || exit 0
cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[ -n "$cmd" ] || exit 0

# The denial text: CLAUDE_HOOK_RULE (set by the Home Manager module's wrapper from noBypass.rule) or this default. It must keep the phrase "Never bypass a macOS block".
RULE=${CLAUDE_HOOK_RULE:-'Rule "Never bypass a macOS block": a macOS block (Gatekeeper, XProtect, a revoked certificate) means STOP and report it to the person; no re-signing third-party code, no quarantine removal, no spctl changes, no retry. Third-party binaries for research run only in a VM or a sandbox, never directly on this machine; agent CLIs come only from pinned, signed sources, never ad hoc npm/bun/pip installs.'}

deny() { # $1 = what was caught
  jq -n --arg r "DENIED ($1). $RULE" '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $r}}'
  exit 0
}

AGENT_PKGS='@openai/codex @anthropic-ai/claude-code @google/gemini-cli opencode-ai opencode cursor-agent @cursor/cli @github/copilot @sourcegraph/amp @qwen-code/qwen-code @augmentcode/auggie aider-chat @continuedev/cli'

is_agent_pkg() { # a token (maybe with @version, ==version, or a path-less spec): 0 if it names an agent CLI package
  local t=$1 p base
  t=${t#\"}; t=${t#\'}; t=${t%\"}; t=${t%\'}
  for p in $AGENT_PKGS; do
    case "$t" in
      "$p"|"$p"@*|"$p"==*|"$p"=*|"$p"\>=*) return 0;;
    esac
  done
  return 1
}

check_words() { # the words of ONE simple command, starting at its command word
  set -f
  # shellcheck disable=SC2086
  set -- $1
  set +f
  # skip wrappers and env assignments in front of the command word
  while [ $# -gt 0 ]; do
    case "$1" in
      sudo|env|command|exec|time|nohup|nice|xargs|builtin) shift; while [ $# -gt 0 ]; do case "$1" in -*) shift;; *=*) shift;; *) break;; esac; done;;
      *=*) shift;;
      *) break;;
    esac
  done
  [ $# -gt 0 ] || return 0
  local w=${1##*/}; shift
  local a
  case "$w" in
    codesign)
      for a in "$@"; do
        case "$a" in
          --force|--remove-signature|--sign|--sign=*|-f|-s) deny "codesign $a";;
          --*) ;;
          -?*) case "${a#-}" in *[fs]*) deny "codesign $a";; esac;;   # combined short flags such as -fs; -dv, -dvvv, -v do not contain f or s
        esac
      done;;
    xattr)
      for a in "$@"; do
        case "$a" in
          --*) ;;
          -?*) case "${a#-}" in *[dc]*) deny "xattr $a";; esac;;      # -d, -c, -dr, -cr, -rd ...; -l, -p, -w, -r, -s, -v are fine
        esac
      done;;
    spctl)
      for a in "$@"; do
        case "$a" in
          --add|--remove|--enable|--disable|--master-disable|--global-disable|--master-enable|--global-enable|--label) deny "spctl $a";;
        esac
      done;;
    npm|pnpm|yarn|bun|bunx|npx|pnpx|pip|pip3|pipx|uv|uvx|cargo)
      local readonly_verb=0 hit=""
      for a in "$@"; do
        case "$a" in
          view|info|show|search|outdated|docs|help|--version|-v) readonly_verb=1;;
        esac
        if is_agent_pkg "$a"; then hit=$a; fi
      done
      [ -n "$hit" ] && [ "$readonly_verb" = 0 ] && deny "$w with the agent CLI package $hit";;
  esac
  return 0
}

scan() { # a command string: split into simple commands and check each; recurse into `sh -c '...'`
  local text=$1 seg rest
  # newlines and the list/pipe operators separate simple commands
  text=${text//$'\n'/;}
  text=${text//&&/;}
  text=${text//||/;}
  text=${text//|/;}
  text=${text//&/;}
  local IFS_SAVE=$IFS
  IFS=';'
  set -f
  # shellcheck disable=SC2086
  set -- $text
  set +f
  IFS=$IFS_SAVE
  for seg in "$@"; do
    seg=${seg#"${seg%%[![:space:]]*}"}
    [ -n "$seg" ] || continue
    seg=${seg#(}; seg=${seg#\{ }; seg=${seg#\$\(}
    check_words "$seg"
  done
}

scan "$cmd"
# the body of `bash -c '...'` / `sh -c "..."` / `zsh -c ...` (and a subshell $( ... )): scan the quoted text as commands too
rest=$cmd
case "$rest" in
  *"-c "*)
    body=${rest#*-c }
    body=${body#\'}; body=${body#\"}; body=${body%\'}; body=${body%\"}
    scan "$body";;
esac
case "$cmd" in
  *'$('*)
    inner=${cmd#*\$\(}; inner=${inner%%)*}
    scan "$inner";;
esac
exit 0
