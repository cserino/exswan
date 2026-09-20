# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1](https://github.com/cserino/exswan/compare/exswan-v0.1.0...exswan-v0.1.1) (2026-09-20)


### Bug Fixes

* bind authentication credentials to users ([#9](https://github.com/cserino/exswan/issues/9)) ([9bb6883](https://github.com/cserino/exswan/commit/9bb68833eecf993239960deb2c97439b5ce6aa59))
* **exswan:** reject malformed client data safely ([#10](https://github.com/cserino/exswan/issues/10)) ([a1e9011](https://github.com/cserino/exswan/commit/a1e9011f72d2abdc768b390a0de3a51886ff9bae))


### Performance Improvements

* **exswan:** reuse decoded authentication inputs ([#12](https://github.com/cserino/exswan/issues/12)) ([ad1d1a2](https://github.com/cserino/exswan/commit/ad1d1a2c1be89c67a6656a11b5bdeb8e4fdd0e38))

## [0.1.0] - 2026-08-12

### Added

- Initial release of the core WebAuthn (FIDO2) library
- Registration and authentication ceremony support
- Attestation formats: `none`, `packed`, `fido-u2f`
- Challenge generation and origin/RP ID validation
- Renamed from `ex_webauthn` / `ExWebauthn` to `exswan` / `ExSwan`
