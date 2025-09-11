{
  pkgs,
  inputs,
  perSystem,
  ...
}:
let
  settingsNix = {
    package = perSystem.nixpkgs.treefmt;

    projectRootFile = ".git/config";

    programs = {
      nixfmt.enable = true;
      deadnix = {
        enable = true;
        no-underscore = true;
      };
      statix.enable = true;

      rustfmt = {
        enable = true;
        edition = "2024";
      };

      gofmt.enable = true;

      shfmt.enable = true;

      taplo.enable = true;

      prettier.enable = true;

      formatjson5.enable = true;

      just.enable = true;
    }
    // pkgs.lib.optionalAttrs (pkgs.system != "riscv64-linux") { shellcheck.enable = true; };

    settings = {
      global.excludes = [
        "LICENSE"
        # unsupported extensions
        "*.{gif,png,svg,tape,mts,lock,mod,sum,env,envrc,gitignore}"

        # link to a read-only store-path
        "treefmt.toml"
      ];

      formatter = {
        deadnix = {
          priority = 1;
        };

        nixfmt = {
          priority = 2;
        };

        statix = {
          priority = 3;
        };

        prettier = {
          options = [
            "--tab-width"
            "2"
          ];
          includes = [ "*.{css,html,js,json,jsx,md,mdx,scss,ts,yaml}" ];
        };
      };
    };
  };

  treefmtEval = inputs.treefmt-nix.lib.evalModule pkgs settingsNix;

in
treefmtEval.config.build.wrapper.overrideAttrs (_: {
  passthru = {
    inherit (treefmtEval.config) package settings;
    inherit (treefmtEval) config;
    inherit settingsNix;
  };
})
