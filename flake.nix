{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config.allowUnfree = true;
        };
        isLinux = pkgs.stdenv.isLinux;
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rust-src"
            "rust-analyzer"
            "clippy"
          ];
        };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rust
            pkgs.pkg-config
          ]
          ++ pkgs.lib.optionals isLinux [
            pkgs.vulkan-loader
            pkgs.vulkan-headers
            pkgs.vulkan-validation-layers
            pkgs.shaderc
            pkgs.libxcb
            pkgs.wayland
            pkgs.wayland-protocols
            pkgs.libxkbcommon
            pkgs.libx11
            pkgs.libxcursor
            pkgs.libxrandr
            pkgs.libxi
          ];

          shellHook = pkgs.lib.optionalString isLinux ''
            export SHADERC_LIB_DIR="${pkgs.shaderc.lib}/lib"
            export LD_LIBRARY_PATH="/run/opengl-driver/lib:${pkgs.vulkan-loader}/lib:${pkgs.wayland}/lib:${pkgs.libxkbcommon}/lib''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          '';
        };
      }
    );
}
