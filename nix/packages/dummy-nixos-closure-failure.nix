{
  pkgs,
  ...
}:

pkgs.writeShellScriptBin "switch-to-configuration" ''
  echo Called with arguments: $@
  echo This would\'ve failed!
  echo This would\'ve failed! >&2
  exit 1
''
