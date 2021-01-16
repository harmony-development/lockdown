{ common }:
with common; with pkgs;
mkDevShell {
  packages =
    [ git nixpkgs-fmt rustc ]
    ++ crateDeps.nativeBuildInputs ++ crateDeps.buildInputs;
  env = { } // env;
}
