{
  pkgs,
  lib,
  ...
}:

{
  i18n.supportedLocales = [
    "en_US.UTF-8/UTF-8"
  ];
  i18n.defaultLocale = "en_US.UTF-8";

  security.sudo.wheelNeedsPassword = false;
  users.users.nixos = {
    openssh.authorizedKeys.keys = [
      # steveej
      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC98w24rC+0YwkR/60VvuHVo+HaojvrM0rre0WCj1s1YVFiLPycsAKhZvl/yo06RKgkhChGb0tHZRGseQSmyb+rEbuNFxXQZnjOylT4jlrQvFR+S9WulkHrLMU0wodwEOpTrzJr/zqThEy3pj61KpC+Yhj9FfCn/p3l7HvL2yp3j+TyclyGbEQtt3Dgo1Ls5ZiD5FVhZAMkto4mK9fThyKjQhT6dUu47j2mxhT5OB8gHNtmPvpdQAUQCNrIz4oP5gilGKsWILmXM0/UwnrSXVdR2cUeiRkKqT0h/Q5jp/+/aW8oDoNYluHw2unWJcMTF0zoVWy/IcuNBTqzfiAhiDICCJN9Y0IXf4KhYN2mGtYJjioEVzmaIp/djxDt1Ra4PTNk1DqazRX72XgXcC9hFskLgiRSGSTR1EJk8dmfN0fE9Kv7IwgmHpyGciUy9WIX4o/eYHt7uO8cmJldtt9dPT7OV3DqGWrmgdCgzV5hVrxPVyOyvuLZa2J1N3T/5v1a8zrsyJ0KwuWH64VJqjVL7dTSKCyHKKIwx5ksLwIpFXBxPiypgCtYyvM6IY7PzF492cBucKimD5wd4f5mY5YxEGZC53/ZgodFVQJkyjmIiO/E06KUjLilmnSzf/nOtk3hoiWK8av47mr8otj+UCfWx6xXVKvGAjSOt4MEzUDDG3D+nw== cardno:17_673_091"
    ];

    # isNormalUser = true;
    # description = "admin";
    # extraGroups = [ "wheel" ];
    # # admin in reverse
    # initialHashedPassword = "$y$j9T$PY2ilEnuQ7epxkrOpfPOy/$nQ.4LJnno8ZpMcHMA1ln/nspBzI.q2PKi/MjPTgvUMB";
    # packages = [ ];
  };

  environment.systemPackages = [
    pkgs.tmux
    pkgs.zenith
  ];

  programs.zsh.enable = true;
  services.openssh.enable = true;

  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.supportedFilesystems = lib.mkForce [
    "ext4"
    "btrfs"
    "vfat"
  ];

  nix.settings = {
    extra-substituters = [
      "https://cache.numtide.com"
    ];
    extra-trusted-public-keys = [
      "niks3.numtide.com-1:DTx8wZduET09hRmMtKdQDxNNthLQETkc/yaX7M4qK0g="
    ];
  };

  isoImage.contents = [
    # Add your placeholder file
    {
      source = pkgs.writeText "data-placeholder" (
        builtins.concatStringsSep "\0" (builtins.genList (_: "0") 1048576)
      );
      target = "/custom-data.bin";
    }

  ];

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "25.11"; # Did you read the comment?
}
