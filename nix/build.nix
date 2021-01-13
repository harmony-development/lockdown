{ release ? false
, doCheck ? false
, doDoc ? false
, common
,
}:
with common;
let
  meta = with pkgs.stdenv.lib; {
    homepage = "https://github.com/harmony-development/lockdown";
    license = licenses.mit;
  };

  package = with pkgs; naersk.buildPackage {
    root = ../.;
    nativeBuildInputs = crateDeps.nativeBuildInputs;
    buildInputs = crateDeps.buildInputs;
    override = (prev: env);
    overrideMain = (prev: {
      inherit meta;
    });
    copyLibs = true;
    inherit release doCheck doDoc;
  };
in
package
