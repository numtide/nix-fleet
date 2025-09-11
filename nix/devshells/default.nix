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
  ];

  # Add environment variables
  env = { };

  # Load custom bash code
  shellHook = '''';
}
