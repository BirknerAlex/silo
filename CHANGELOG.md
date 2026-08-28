# Changelog

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
