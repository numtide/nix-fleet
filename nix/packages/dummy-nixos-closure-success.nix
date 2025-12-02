{
  pkgs,
  ...
}:

pkgs.writeShellScriptBin "switch-to-configuration" ''
  echo Called with arguments: $@
  echo This would\'ve switched the system, congratulations!
  exit 0
''
