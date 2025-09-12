{
  pkgs,
  flake,
  system,
}:
pkgs.mkShell {
  # Add build dependencies
  packages = [
    flake.formatter.${system}
    pkgs.jq
    pkgs.nil

    pkgs.facter
    pkgs.nixos-facter
  ];

  # Add environment variables
  env = { };

  # Load custom bash code
  shellHook = '''';
}
