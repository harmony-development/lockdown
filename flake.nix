{
  description = "Flake for lockdown";

  inputs = {
    devshell.url = "github:numtide/devshell";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    naersk = {
      url = "github:nmattia/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flakeUtils.url = "github:numtide/flake-utils";
    nixpkgsMoz = {
      url = "github:mozilla/nixpkgs-mozilla";
      flake = false;
    };
  };

  outputs = inputs: with inputs;
    with flakeUtils.lib;
    eachSystem defaultSystems (system:
      let
        common = import ./nix/common.nix {
          sources = { inherit devshell naersk nixpkgs nixpkgsMoz; };
          inherit system;
        };

        packages = {
          # Compiles slower but has tests and faster executable
          lockdown = import ./nix/build.nix {
            inherit common;
            doCheck = true;
            release = true;
          };
          # Compiles faster but no tests and slower executable
          lockdown-debug = import ./nix/build.nix { inherit common; };
          # Compiles faster but has tests and slower executable
          lockdown-tests = import ./nix/build.nix { inherit common; doCheck = true; };
        };

      in
      {
        inherit packages;

        # Release build is the default package
        defaultPackage = packages.lockdown;

        devShell = import ./nix/devShell.nix { inherit common; };
      }
    );
}
