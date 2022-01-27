{ system ? builtins.currentSystem
, obelisk ? import ./.obelisk/impl {
    inherit system;
    iosSdkVersion = "13.2";

    # You must accept the Android Software Development Kit License Agreement at
    # https://developer.android.com/studio/terms in order to build Android apps.
    # Uncomment and set this to `true` to indicate your acceptance:
    # config.android_sdk.accept_license = false;

    # In order to use Let's Encrypt for HTTPS deployments you must accept
    # their terms of service at https://letsencrypt.org/repository/.
    # Uncomment and set this to `true` to indicate your acceptance:
    # terms.security.acme.acceptTerms = false;
  }
}:
with obelisk;
project ./. ({ pkgs, hackGet, ... }:
let inherit (pkgs.haskell.lib) doJailbreak dontCheck;
    webauthn-overrides = self: super: {
      webauthn = doJailbreak (self.callHackageDirect {
        pkg = "webauthn";
        ver = "0.1.1.0";
        # sha256 = "0y4ppgh77zl6wwawjbrczfkdax2zv3rwxcy2mizpvx3gwlbcj6ac";
        sha256 = "16v43gsm9qkcqmbm23lsr0rzsvg2m4hbk3qyqfqj1k8r2vnpi2ys";
      } {});
      beam-automigrate = doJailbreak super.beam-automigrate;
      hspec-expectations-json = doJailbreak super.hspec-expectations-json;
      resolv = doJailbreak super.resolv;
      websockets = doJailbreak super.websockets;
      jsaddle = doJailbreak super.jsaddle;
      heist = dontCheck super.heist;
      warp = dontCheck (self.callHackage "warp" "3.3.18" {});
      # serialise = doJailbreak super.serialise;
      http2 = self.callHackage "http2" "3.0.2" {};

      snap-extras = doJailbreak (self.callHackage "snap-extras" "0.12.3.0" {});
      jmacro = self.callHackage "jmacro" "0.6.17" {};
      parseargs = self.callHackage "parseargs" "0.2.0.8" {};
      aeson-gadt-th = self.callHackage "aeson-gadt-th" "0.2.5.0" {};

      base16-bytestring = self.callHackage "base16-bytestring" "1.0.2.0" {};
      base64-bytestring = self.callHackage "base64-bytestring" "1.2.1.0" {};
      cborg = self.callHackage "cborg" "0.2.6.0" {};
      cryptonite = self.callHackage "cryptonite" "0.29" {};
      file-embed = self.callHackage "file-embed" "0.0.15.0" {};
      jose = self.callHackage "jose" "0.8.5" {};
      serialise = doJailbreak(self.callHackage "serialise" "0.2.4.0" {});
      strict = self.callHackage "strict" "0.4.0.1" {};
      uuid = dontCheck (self.callHackage "uuid" "1.3.15" {});
      uuid-types = dontCheck (self.callHackage "uuid-types" "1.0.5" {});
      validation = self.callHackage "validation" "1.1.2" {};
      cryptohash-md5 = dontCheck super.cryptohash-md5;
      cryptohash-sha1 = dontCheck super.cryptohash-sha1;
      aeson = doJailbreak super.aeson;
      deriving-aeson = self.callHackage "deriving-aeson" "0.2.8" {};
      unordered-containers = self.callHackage "unordered-containers" "0.2.16.0" {};
      x509-validation = self.callHackageDirect {
        pkg = "x509-validation";
        ver = "1.6.12";
        sha256 = "1jrsryn6hfdmr1b1alpj5zxvw26dw8y7kqpq555q2njm3kvwmxap";
      } {};
    };
in
{
  overrides = webauthn-overrides;
  android.applicationId = "systems.obsidian.obelisk.examples.minimal";
  android.displayName = "Obelisk Minimal Example";
  ios.bundleIdentifier = "systems.obsidian.obelisk.examples.minimal";
  ios.bundleName = "Obelisk Minimal Example";
})
