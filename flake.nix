{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    # OpenROAD alone, from a revision Hydra built it at: at the main pin its
    # dependency or-tools is marked broken, so nothing there evaluates or is
    # cached (ledger O1).
    nixpkgs-openroad.url = "github:NixOS/nixpkgs/f45c6f04c2f013f004bf94e284e95d72898d9393";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      nixpkgs-openroad,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree = true;
        };
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "clippy"
          ];
        };
      in
      let
        tools = [
          rust
          pkgs.pkg-config
          # Mutation testing is the acceptance gate for the test suite: a
          # suite is only as strong as the logic changes it actually catches,
          # and this measures that instead of assuming it.
          pkgs.cargo-mutants
        ];
      in
      {
        devShells.default = pkgs.mkShell { buildInputs = tools; };
        # The independent tools the nightly differential tests compare against
        # (docs/testing-plan.md L6): `nix develop .#oracles`, then
        # `cargo test -- --ignored`. Pinned by flake.lock, so an oracle's
        # version changes only in a reviewed commit.
        devShells.oracles = pkgs.mkShell {
          buildInputs = tools ++ [
            pkgs.klayout
            pkgs.magic-vlsi
            pkgs.netgen-vlsi
            pkgs.ngspice
            # FastCap and FastHenry, MIT's field solvers; FasterCap, the
            # plan's first choice for capacitance, is not packaged.
            pkgs.fastcap
            pkgs.fasthenry
            # OpenROAD's antenna checker and PDNSim, and Yosys `check`: the
            # ERC differentials (ledger O1).
            nixpkgs-openroad.legacyPackages.${system}.openroad
            pkgs.yosys
          ];
        };
      }
    );
}
