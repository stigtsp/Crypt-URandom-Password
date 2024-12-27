{ pkgs ? import <nixpkgs> {} }:

with pkgs;

let perl' = perl.withPackages(p: [ p.CryptURandom p.TestException ]);
in mkShell {
  buildInputs = [ perl' ];
}
