{ inputs, flake, ... }:

{
  mkCraneLib =
    { pkgs, system }:
    let
      craneLib = inputs.crane.mkLib pkgs;
      toolchain = (inputs.rust-overlay.lib.mkRustBin { } pkgs).fromRustupToolchainFile (
        flake + "/rust-toolchain.toml"
      );
    in
    craneLib.overrideToolchain toolchain;
}
