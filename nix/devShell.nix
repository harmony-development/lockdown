{ common }:
with common; with pkgs;
mkShell {
  nativeBuildInputs =
    [ git nixpkgs-fmt cargo rustc ]
    ++ crateDeps.nativeBuildInputs;
  buildInputs = crateDeps.buildInputs;
  shellHook =
    let
      varList = lib.mapAttrsToList (name: value: ''export ${name}="${value}"'') env;
      varConcatenated = lib.concatStringsSep "\n" varList;
    in
    ''
      export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:${lib.makeLibraryPath neededLibs}";

      ${varConcatenated}
    '';
}
