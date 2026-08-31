# Changelog

## [0.7.1](https://github.com/BirknerAlex/silo/compare/v0.7.0...v0.7.1) (2026-08-31)


### Bug fixes

* **deps:** bump jsonwebtoken to 11 to address type confusion advisory ([5829023](https://github.com/BirknerAlex/silo/commit/582902304cc88f0e1947e88a1bad81d76031a2aa))
* **helm:** expose config.prune / config.jobs via structured values ([aed691c](https://github.com/BirknerAlex/silo/commit/aed691c1ecfa7de35bbafcf738c98fc1e8f1d27c)), closes [#30](https://github.com/BirknerAlex/silo/issues/30)
* **security:** close privilege-escalation and disclosure paths found in an audit ([051f3e3](https://github.com/BirknerAlex/silo/commit/051f3e31e7001086fe9758007b2c61536a08852c))

## [0.7.0](https://github.com/BirknerAlex/silo/compare/v0.6.0...v0.7.0) (2026-08-30)


### Features

* **prune:** add retention-based package pruning ([3705ee1](https://github.com/BirknerAlex/silo/commit/3705ee156633393fb144a7ad31e8511d2703f65b))


### Bug fixes

* **prune:** enforce repo scope on prune admin RPCs, fix stale scheduler clock ([e59dd2a](https://github.com/BirknerAlex/silo/commit/e59dd2adcce8f478e535e055b822e0ee616e837e))

## [0.6.0](https://github.com/BirknerAlex/silo/compare/v0.5.3...v0.6.0) (2026-08-30)


### Features

* **npm:** support npm publish/yarn publish over HTTP ([fda474f](https://github.com/BirknerAlex/silo/commit/fda474f4d4d81b32500d80a3cc8621e51ef22d58))
* **pacman:** add Arch Linux pacman repo support ([3e95dfa](https://github.com/BirknerAlex/silo/commit/3e95dfa9e7dc8d8b95b7f4d09c5127ab58654911))
* **repos:** replace global anonymous-read with per-repo public/private mode ([f4e33b4](https://github.com/BirknerAlex/silo/commit/f4e33b46c32efb4a21b37488ccebe8651b82dead))

## [0.5.3](https://github.com/BirknerAlex/silo/compare/v0.5.2...v0.5.3) (2026-08-28)


### Bug fixes

* **cli:** support real TLS for https:// server addresses ([36a7275](https://github.com/BirknerAlex/silo/commit/36a72751ba1e12713a13cbba5772c44d30419ad0))

## [0.5.2](https://github.com/BirknerAlex/silo/compare/v0.5.1...v0.5.2) (2026-08-28)


### Bug fixes

* **ci:** scope release artifact download to silo-* binaries ([4cbc4a3](https://github.com/BirknerAlex/silo/commit/4cbc4a30dc67fe273e7f995fd2278743e5663adb))

## [0.5.1](https://github.com/BirknerAlex/silo/compare/v0.5.0...v0.5.1) (2026-08-28)


### Bug fixes

* **docker:** ensure copied binaries are executable ([e745eeb](https://github.com/BirknerAlex/silo/commit/e745eebac19a00e20ff5f115871c65cbe067abaf))

## [0.5.0](https://github.com/BirknerAlex/silo/compare/v0.4.2...v0.5.0) (2026-08-28)


### Features

* **server:** serve gRPC and HTTP on one port ([0ef6663](https://github.com/BirknerAlex/silo/commit/0ef6663bee151ecf79515397c525e6612b8233a6))


### Bug fixes

* **ci:** build release image binaries natively instead of under QEMU ([980296e](https://github.com/BirknerAlex/silo/commit/980296eb4b94e8a21b19645f100ae064ce4461c7))

## [0.4.2](https://github.com/BirknerAlex/silo/compare/v0.4.1...v0.4.2) (2026-08-28)


### Bug fixes

* **chart:** default image.repository to the real Docker Hub org ([bfcce74](https://github.com/BirknerAlex/silo/commit/bfcce74c48ca677c12564f6ca9ad379a05357f21))

## [0.4.1](https://github.com/BirknerAlex/silo/compare/v0.4.0...v0.4.1) (2026-08-28)


### Bug fixes

* **ci:** tag the released image with its version, not just latest ([614c6a5](https://github.com/BirknerAlex/silo/commit/614c6a5629f106b7fdba2a89830e24debcde44ec))

## [0.4.0](https://github.com/BirknerAlex/silo/compare/v0.3.0...v0.4.0) (2026-08-27)


### Features

* **ci:** build a Windows CLI binary and fix the release dispatch ([41ecb7c](https://github.com/BirknerAlex/silo/commit/41ecb7c777df6c6e2357fce65252e541328fc13d))


### Bug fixes

* **ci:** use a real Unix epoch for SOURCE_DATE_EPOCH ([ee2357c](https://github.com/BirknerAlex/silo/commit/ee2357cf8047dc95fd86e46dc9be77719ce35469))


### Documentation

* **ci:** correct the release-please strategy comment ([0c0ac73](https://github.com/BirknerAlex/silo/commit/0c0ac7383af1309dfdfb8f5fcda73469922c35f5))

## [0.3.0](https://github.com/BirknerAlex/silo/compare/v0.2.0...v0.3.0) (2026-08-27)


### Features

* Silo — a self-hosted RPM, APK and npm registry ([c6b4c8f](https://github.com/BirknerAlex/silo/commit/c6b4c8f0623c06541b4c570534258687127c0ba3))
