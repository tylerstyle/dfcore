{
  description = "Shared forensic safety core for dfnix tools";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dfcore = pkgs.callPackage ./package.nix { };
      in
      {
        packages = {
          default = dfcore;
          inherit dfcore;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ dfcore ];
          buildInputs = with pkgs; [ rustc cargo rustfmt clippy ];
        };
      }
    );
}
