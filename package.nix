{ lib
, rustPlatform
, makeWrapper
, util-linux
}:

rustPlatform.buildRustPackage {
  pname = "dfcore";
  version = "0.2.0";

  src = lib.cleanSource ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  nativeBuildInputs = [ makeWrapper ];

  postInstall = ''
    # dfcore-protect reads the device tree with lsblk
    wrapProgram $out/bin/dfcore-protect \
      --prefix PATH : ${lib.makeBinPath [ util-linux ]}
  '';

  meta = with lib; {
    description = "Shared forensic safety core for dfnix tools (device topology, protected-device registry, audit log)";
    homepage = "https://github.com/tylerstyle/dfcore";
    license = with licenses; [ mit asl20 ];
    mainProgram = "dfcore-audit";
    platforms = platforms.linux;
  };
}
