# claude-code-hooks

Claude Code `PreToolUse(Bash)` hooks as pinned binaries, with a Home Manager module.

| binary | does |
|---|---|
| `claude-hook-allow-readonly-reads` | approves genuinely read-only commands (allowlist; never denies), so a leading `cd` does not stall a session on a prompt |
| `claude-hook-auto-background-bash` | rewrites a short list of known-slow commands to `run_in_background` |
| `claude-hook-no-bypass-macos-blocks` | denies `codesign --force`/`-s`, `xattr -d/-c`, `spctl --add/--master-disable`, and ad hoc installs of agent CLIs |
| `claude-hook-no-adhoc-notifications` | denies an agent's own `osascript display notification`, `terminal-notifier`, `alerter` |

Every hook fails open (no output, exit 0) on a parse problem; register each with `2>/dev/null || true`, because a hook
that exits 2 blocks the tool call. The deny guards are regexes over the command string: they stop an honest agent
reaching for the wrong tool, not a determined one (see the scripts' HONEST LIMITS).

```nix
inputs.claude-code-hooks = { url = "github:bdelanghe/claude-code-hooks"; inputs.nixpkgs.follows = "nixpkgs"; inputs.home-manager.follows = "home-manager"; };
# modules = [ claude-code-hooks.homeManagerModules.default ];
programs.claudeCodeHooks = {
  enable = true;
  # register the two deny guards additively in these files at each switch (never created, never overwritten)
  settingsFiles = [ "${config.home.homeDirectory}/.claude/settings.json" ];
  noBypass.rule = "Never bypass a macOS block: ...";        # optional: your own denial text
  noAttribution.enable = true;                               # optional: includeCoAuthoredBy = false, attribution.{commit,pr} = ""
};
```

The two other hooks are registered by hand in `settings.json`, e.g.
`{"matcher":"Bash","hooks":[{"type":"command","command":"claude-hook-allow-readonly-reads 2>/dev/null || true"}]}`.

## Checks

`nix flake check`: the module under Home Manager (any system), and on macOS the goldens + mutation tests of the two deny guards.
