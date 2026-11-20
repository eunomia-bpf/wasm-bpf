{
  description = "wasm-bpf packages and dev shell flake";

  outputs =
    { self
    , fenix
    , flake-utils
    , naersk
    , nixpkgs
    }:
    # Each of these is named explicitly rather than taken from
    # eachDefaultSystem: the nixpkgs this flake now pins dropped
    # x86_64-darwin, so `legacyPackages.x86_64-darwin` throws and
    # `nix flake show --all-systems` fails evaluation. The other three are
    # flake-utils' defaults.
    flake-utils.lib.eachSystem [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ] (system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
      toolchain = with fenix.packages.${system}; combine [
        minimal.cargo
        minimal.rustc
      ];
      fenix-naersk = naersk.lib.${system}.override {
        cargo = toolchain;
        rustc = toolchain;
      };
    in
    {
      packages = rec {
        wasm-bpf = fenix-naersk.buildPackage {
          pname = "wasm-bpf";
          hardeningDisable = [ "all" ];
          cargoBuildOptions = x: x ++ [ "-p" "wasm-bpf" ];
          buildInputs = with pkgs; [
            zlib
          ];
          nativeBuildInputs = with pkgs; [
            clang
            elfutils
            pkg-config
          ];
          src = ./runtime;
        };

        default = wasm-bpf;
      };

      devShell = pkgs.mkShell {
        buildInputs = with pkgs; [
          toolchain
          zlib
          openssl
        ];
        nativeBuildInputs = with pkgs; [
          clang
          elfutils
          pkg-config
        ];
      };
    }
    );

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
    naersk = {
      url = "github:nix-community/naersk";
      inputs.fenix.follows = "fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };
}

