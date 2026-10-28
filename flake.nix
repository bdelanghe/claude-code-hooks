{
  description = "claude-code-hooks: Claude Code PreToolUse hooks (read-only approvals, auto-background, macOS-block and ad-hoc-notification guards) as a Home Manager module";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    # Only for the module-eval check; consumers already carry home-manager and should `follows` it.
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, home-manager }:
    let
      lib = nixpkgs.lib;
      systems = [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ];
      forAll = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      homeManagerModules.default = import ./nix/module.nix;

      checks = forAll (pkgs:
        let
          hm = extra: home-manager.lib.homeManagerConfiguration {
            inherit pkgs;
            modules = [ self.homeManagerModules.default
              { home = { username = "t"; homeDirectory = "/home/t"; stateVersion = "24.11"; }; programs.claudeCodeHooks.enable = true; }
              extra ];
          };
          on = hm {
            programs.claudeCodeHooks = { settingsFiles = [ "/home/t/a.json" "/home/t/b.json" ];
              noBypass.rule = "Never bypass a macOS block: custom"; noAttribution.enable = true; };
          };
          off = hm { };
          bin = cfg: name: lib.findFirst (p: (p.name or "") == name) (throw "no ${name}") cfg.config.home.packages;
          act = on.config.home.activation;
        in
        {
          # The module under Home Manager: binaries installed, the custom rule reaches its hook, registration only when settingsFiles is set.
          module-eval =
            assert act ? claudeNoBypassHook && act ? claudeNoAdhocNotificationsHook && act ? claudeNoAttribution;
            assert lib.hasInfix ''"/home/t/a.json" \'' act.claudeNoBypassHook.data;
            assert lib.hasInfix "/home/t/.nix-profile/bin/claude-hook-no-adhoc-notifications" act.claudeNoAdhocNotificationsHook.data;
            assert lib.hasInfix ''"/home/t/b.json"'' act.claudeNoAttribution.data;
            assert !(off.config.home.activation ? claudeNoBypassHook) && !(off.config.home.activation ? claudeNoAttribution);
            pkgs.runCommand "claude-code-hooks-module-eval" { } ''
              grep -qF "CLAUDE_HOOK_RULE='Never bypass a macOS block: custom'" ${bin on "claude-hook-no-bypass-macos-blocks"}/bin/claude-hook-no-bypass-macos-blocks
              ! grep -q CLAUDE_HOOK_RULE= ${bin off "claude-hook-no-bypass-macos-blocks"}/bin/claude-hook-no-bypass-macos-blocks
              ${lib.concatMapStrings (h: "${pkgs.bash}/bin/bash -n ${bin off h}/bin/${h}\n")
                [ "claude-hook-allow-readonly-reads" "claude-hook-auto-background-bash" "claude-hook-no-bypass-macos-blocks" "claude-hook-no-adhoc-notifications" ]}
              touch $out
            '';
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
          # The goldens + mutation tests, against the real scripts (macOS: they use BSD /usr/bin/stat and osascript names).
          tests = pkgs.runCommand "claude-code-hooks-tests"
            { src = lib.fileset.toSource { root = ./.; fileset = lib.fileset.unions [ ./hooks ./tests ]; }; nativeBuildInputs = [ pkgs.jq pkgs.bash ]; }
            ''
              export PATH="$PATH:/usr/bin:/bin" HOME="$TMPDIR/home"; mkdir -p "$HOME"
              cp -R "$src/." "$TMPDIR/r"; chmod -R u+w "$TMPDIR/r"; cd "$TMPDIR/r"
              for t in tests/*.sh; do echo "== $t"; bash "$t" || { echo "FAILED $t"; exit 1; }; done
              touch $out
            '';
        });
    };
}
