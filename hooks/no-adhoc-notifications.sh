#!/usr/bin/env bash
# PreToolUse(Bash) hook: DENY a hand-raised macOS notification banner from an agent's own Bash call (an agent that runs
# `osascript -e 'display notification ...'` to get the person's attention, instead of asking in its reply or using their notification channel).
#
# WHAT IT DENIES (a command, or any segment of a pipeline / `;` / `&&` list, or the body of `bash -c '...'` / `$( ... )`, whose command word is):
#   osascript         whose arguments contain AppleScript `display notification`   (other osascript, including `display dialog`, the decision signer's prompt, is allowed)
#   terminal-notifier, alerter   (any use)
# Everything else prints nothing and exits 0 ("no decision"). The denial says what to do instead (noAdhocNotifications.rule).
#
# HONEST LIMITS: a regex over the command string, like no-bypass-macos-blocks.sh. It stops an agent that reaches for osascript out of habit and puts the rule in front of it; it does not
# stop `eval`, a script file written first, or another language. FAILS OPEN on a parse problem (registered with `|| true`; a hook that exits 2 blocks the call). Bash 3.2 safe.
input=$(cat 2>/dev/null) || exit 0
cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[ -n "$cmd" ] || exit 0

# The denial text: CLAUDE_HOOK_RULE (set by the Home Manager module's wrapper from noAdhocNotifications.rule) or this default. It must keep the phrase "No ad-hoc desktop notifications".
RULE=${CLAUDE_HOOK_RULE:-'No ad-hoc desktop notifications: do not raise a macOS banner with osascript `display notification`, terminal-notifier or alerter. If the person is reading this session, ask in your reply; if it must reach them elsewhere, use the notification channel they set up.'}

deny() { # $1 = what was caught
  jq -n --arg r "DENIED ($1). $RULE" '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $r}}'
  exit 0
}

check_words() { # ONE simple command, starting at its command word
  local seg=$1
  set -f
  # shellcheck disable=SC2086
  set -- $seg
  set +f
  while [ $# -gt 0 ]; do
    case "$1" in
      sudo|env|command|exec|time|nohup|nice|xargs|builtin) shift; while [ $# -gt 0 ]; do case "$1" in -*) shift;; *=*) shift;; *) break;; esac; done;;
      *=*) shift;;
      *) break;;
    esac
  done
  [ $# -gt 0 ] || return 0
  local w=${1##*/}; shift
  case "$w" in
    osascript) printf '%s' "$*" | grep -Eiq 'display[[:space:]]+notification' && deny "osascript display notification";;
    terminal-notifier|alerter) deny "$w";;
  esac
  return 0
}

scan() { # a command string: split into simple commands and check each
  local text=$1 seg
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
case "$cmd" in
  *"-c "*)
    body=${cmd#*-c }
    body=${body#\'}; body=${body#\"}; body=${body%\'}; body=${body%\"}
    scan "$body";;
esac
case "$cmd" in
  *'$('*)
    inner=${cmd#*\$\(}; inner=${inner%%)*}
    scan "$inner";;
esac
exit 0
