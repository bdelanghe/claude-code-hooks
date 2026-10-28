{ config, lib, pkgs, ... }:

# claude-code-hooks: Claude Code hook scripts as pinned binaries, plus the additive registration of the two deny guards.
#
# NIX OWNS THE SCRIPT (pinned, reviewable, reproducible); settings.json keeps a one-line registration by stable name.
# settings.json itself is never declared: Claude Code writes that file at runtime (a read-only store symlink would break
# those writes), so the activation steps here only MERGE an entry in, and only when absent.
#
# writeShellScriptBin, NOT writeShellApplication: the latter injects `set -euo pipefail`, and these hooks use non-zero exit
# as ordinary control flow (a `grep -q` that finds nothing is the common case). PATH is stripped to jq + /usr/bin + /bin:
# hook processes do not inherit a login PATH, and /usr/bin's BSD grep is what the auto-background regex was written against.
#
# Every registration ends in `2>/dev/null || true`: a PreToolUse hook that exits 2 BLOCKS the tool call, and a bash syntax
# error exits 2. A deny is a JSON decision on stdout with exit 0, which `|| true` does not disturb.
let
  cfg = config.programs.claudeCodeHooks;
  mkHook = name: file: rule: pkgs.writeShellScriptBin name (''
    PATH="${pkgs.jq}/bin:/usr/bin:/bin"
    export PATH
  '' + lib.optionalString (rule != null) ''
    CLAUDE_HOOK_RULE=${lib.escapeShellArg rule}
  '' + ''
    ${builtins.readFile file}
  '');
  profileBin = "${config.home.homeDirectory}/.nix-profile/bin";
  register = env: ''
    JQ=${pkgs.jq}/bin/jq ${env} ${pkgs.bash}/bin/bash ${../hooks/register-no-bypass-hook.sh} \
      ${lib.concatMapStringsSep " \\\n  " (f: ''"${f}"'') cfg.settingsFiles}
  '';
  ruleOption = what: lib.mkOption {
    type = lib.types.nullOr lib.types.str;
    default = null;
    description = "The denial text for ${what} (null = the script's own generic text).";
  };
in
{
  options.programs.claudeCodeHooks = {
    enable = lib.mkEnableOption "the Claude Code hook binaries (claude-hook-allow-readonly-reads, -auto-background-bash, -no-bypass-macos-blocks, -no-adhoc-notifications)";
    settingsFiles = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Claude settings.json files the deny guards are registered in at each switch (additively; a missing file is not created).";
    };
    noBypass.rule = ruleOption "claude-hook-no-bypass-macos-blocks (must keep the phrase \"Never bypass a macOS block\")";
    noAdhocNotifications.rule = ruleOption "claude-hook-no-adhoc-notifications (must keep the phrase \"No ad-hoc desktop notifications\")";
    noAttribution = {
      enable = lib.mkEnableOption "patching includeCoAuthoredBy = false and attribution.{commit,pr} = \"\" into settingsFiles at each switch";
      settingsFiles = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = cfg.settingsFiles;
        defaultText = lib.literalExpression "config.programs.claudeCodeHooks.settingsFiles";
        description = "Settings files to patch (only existing files; every other key is left untouched).";
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf cfg.enable {
      home.packages = [
        # PreToolUse(Bash): approve genuinely read-only commands (never denies; an allow outranks deny rules, so its secret-path rejects are load-bearing).
        (mkHook "claude-hook-allow-readonly-reads" ../hooks/allow-readonly-reads.sh null)
        # PreToolUse(Bash): rewrite known-slow commands to run_in_background.
        (mkHook "claude-hook-auto-background-bash" ../hooks/auto-background-bash.sh null)
        # PreToolUse(Bash): DENY macOS-block bypasses and ad hoc installs of agent CLIs.
        (mkHook "claude-hook-no-bypass-macos-blocks" ../hooks/no-bypass-macos-blocks.sh cfg.noBypass.rule)
        # PreToolUse(Bash): DENY an agent's hand-raised macOS banner.
        (mkHook "claude-hook-no-adhoc-notifications" ../hooks/no-adhoc-notifications.sh cfg.noAdhocNotifications.rule)
      ];
    })
    (lib.mkIf (cfg.enable && cfg.settingsFiles != [ ]) {
      home.activation.claudeNoBypassHook = lib.hm.dag.entryAfter [ "writeBoundary" ]
        (register ''NOBYPASS_CMD="${profileBin}/claude-hook-no-bypass-macos-blocks"'');
      home.activation.claudeNoAdhocNotificationsHook = lib.hm.dag.entryAfter [ "writeBoundary" ]
        (register ''HOOK_CMD="${profileBin}/claude-hook-no-adhoc-notifications"'');
    })
    (lib.mkIf cfg.noAttribution.enable {
      home.activation.claudeNoAttribution = lib.hm.dag.entryAfter [ "writeBoundary" ]
        (lib.concatMapStrings (f: ''
          if [ -f "${f}" ]; then
            tmp=$(mktemp)
            ${pkgs.jq}/bin/jq '.includeCoAuthoredBy = false | .attribution.commit = "" | .attribution.pr = ""' \
              "${f}" > "$tmp" && mv "$tmp" "${f}"
          fi
        '') cfg.noAttribution.settingsFiles);
    })
  ];
}
