{
  description = "Sensor Watch development and build flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-23.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    let
      mkDevShells = buildPlatform:
        let
          overlays = [ rust-overlay.overlays.default ];
          pkgs = import nixpkgs {
            inherit overlays; system = buildPlatform;
          };
          rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          inputs = [
            pkgs.bitcoind
            pkgs.clang
            pkgs.glibc_multi
            pkgs.just
            pkgs.openssl
            pkgs.pkg-config
            pkgs.rust-analyzer
            rust
          ];
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = inputs;
          };
        };
    in
    flake-utils.lib.eachDefaultSystem (system: {
      devShells = mkDevShells system;
    });
}
