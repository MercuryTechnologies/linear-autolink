{
  description = "Script to create GitHub autolinks for Linear teams";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # for mystery reasons, you can't update a nested flake input??
    pypi-deps-db = {
      owner = "DavHau";
      repo = "pypi-deps-db";
      type = "github";
    };
    mach-nix = {
      url = "github:DavHau/mach-nix";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
      inputs.pypi-deps-db.follows = "pypi-deps-db";
    };
  };

  outputs = { self, nixpkgs, flake-utils, mach-nix, ... }:
    let
      out = system:
        let
          pkgs = import nixpkgs {
            inherit system;
            # overlays = [ self.overlays.default ];
          };
        in
        {
          packages.default = mach-nix.lib."${system}".buildPythonApplication {
            pname = "linear-autolink";
            src = ./.;
          };
          inherit pkgs;
          # tools that should be added to the shell
          devShells.default = mach-nix.lib."${system}".mkPythonShell {
            requirements = ''
              requests
              pyjwt
              cryptography
              ipython
              yapf
            '';
          };
        };
    in
    flake-utils.lib.eachDefaultSystem out;
}
