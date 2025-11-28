{
  inputs,
  pkgs,
  perSystem,
  ...
}:

(inputs.nixpkgs.lib.nixosSystem {
  inherit (pkgs.stdenv.targetPlatform) system;
  modules = [
    (
      { modulesPath, ... }:
      {

        imports = [
          inputs.srvos.nixosModules.mixins-nix-experimental
          {
            nix.settings.experimental-features = [
              "nix-command"
              "flakes"
            ];
          }

          (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix")
          (modulesPath + "/profiles/minimal.nix")

          ./nixos-installer/configuration.nix

          {
            # Remove perl from activation
            boot.initrd.systemd.enable = true;
            system.etc.overlay.enable = true;
            services.userborn.enable = true;

            # Random perl remnants
            system.tools.nixos-generate-config.enable = false;
            boot.loader.grub.enable = false;
            environment.defaultPackages = [ ];
            documentation.info.enable = false;
            documentation.nixos.enable = false;
          }
        ];

        nix = {
          enable = true;
          settings = {

          };
        };

        # TODO: some day this won't be needed for an install
        system.disableInstallerTools = false;
        programs.nano.enable = false;
        programs.fuse.enable = false;
        security.sudo.enable = true;
        networking.firewall.enable = false;

        environment.systemPackages = [
          perSystem.self.rust-workspace
        ];
      }
    )
  ];
})
