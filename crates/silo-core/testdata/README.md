# testdata

`apk-signing-key.pem` is a throwaway 2048-bit RSA key used only by
`silo-core`'s unit tests to exercise APKINDEX signing. It signs nothing
real and is intentionally checked in so the test suite doesn't spend
seconds generating a key on every run. Do not use it for anything.

`gpg-signing-key.asc` is a throwaway armored OpenPGP secret key, used the
same way and for the same reason: `silo-core`'s tests need a parseable key
to exercise RPM/repomd signing and the public-key derivation behind
`/RPM-GPG-KEY-silo`, and generating one costs seconds per run. It has no
passphrase and signs nothing real. Do not use it for anything.
