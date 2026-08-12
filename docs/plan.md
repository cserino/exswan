# ExSwan Project Plan

## Overview

ExSwan is an Elixir library for implementing WebAuthn (Web Authentication) specification, enabling passwordless authentication using FIDO2/WebAuthn standards.

## Project Goals

- Provide a tested WebAuthn server implementation for Elixir applications
- Support both authentication and registration ceremonies
- Track protocol requirements and conformance evidence explicitly
- Offer simple, developer-friendly APIs
- Support multiple authenticator types (platform, cross-platform)

## Current State

- Monorepo of standalone Hex packages under `packages/` (not an OTP umbrella)
- Core package `:exswan` (`ExSwan.*`) with registration/authentication ceremonies
- Plug package `:exswan_plug` (`ExSwan.Plug`) for ceremony lifecycle helpers
- Path vs Hex deps controlled by `EXSWAN_MONOREPO`
- Root `Makefile` + GitHub Actions matrix CI

## Phase 1: Core Infrastructure (Weeks 1-2)

### 1.1 Dependencies & Setup

- Add required dependencies:
  - `jason` for JSON handling
  - `cbor` for CBOR encoding/decoding
  - `x509` for certificate validation
  - `crypto` (built-in) for cryptographic operations
- Configure hex package metadata
- Set up comprehensive test suite structure

### 1.2 Data Structures

- Define WebAuthn credential structures
- Create attestation and assertion data types
- Implement CBOR encoding/decoding for WebAuthn objects
- Add validation functions for WebAuthn data

## Phase 2: Registration Flow (Weeks 3-4)

### 2.1 Credential Creation Options

- Generate challenge values
- Build `PublicKeyCredentialCreationOptions`
- Support authenticator selection criteria
- Handle user and relying party information

### 2.2 Attestation Processing

- Parse attestation responses
- Validate attestation statements
- Support `none` attestation; add other formats only with complete trust-rule coverage
- Store and manage public keys

## Phase 3: Authentication Flow (Weeks 5-6)

### 3.1 Assertion Options

- Generate authentication challenges
- Build `PublicKeyCredentialRequestOptions`
- Handle user verification requirements
- Support credential filtering

### 3.2 Assertion Verification

- Validate assertion responses
- Verify digital signatures
- Check authenticator data
- Handle counter validation

## Phase 4: Security & Standards Compliance (Weeks 7-8)

### 4.1 Security Features

- Implement origin validation
- Add replay attack protection
- Ensure secure random challenge generation
- Validate certificate chains

### 4.2 Protocol and Conformance Evidence

- WebAuthn Level 2 compatibility baseline
- Generated SimpleWebAuthn fixtures and a private FIDO conformance harness
- Comprehensive error handling
- Security audit and testing

## Phase 5: Integration & Documentation (Weeks 9-10)

### 5.1 Framework Integration

- Phoenix integration helpers
- Plug middleware for WebAuthn flows
- Session management utilities
- Example applications

### 5.2 Documentation & Testing

- Complete API documentation
- Integration guides and tutorials
- Comprehensive test coverage (>95%)
- Performance benchmarks

## Technical Architecture

```
exswan/                              # git monorepo
├── packages/
│   ├── exswan/                      # :exswan (core Hex package)
│   │   ├── ExSwan                   # Public API surface
│   │   ├── ExSwan.Credential        # Core credential management
│   │   ├── ExSwan.Registration      # Registration ceremony
│   │   ├── ExSwan.Authentication    # Authentication ceremony
│   │   ├── ExSwan.Attestation*      # Attestation validation
│   │   └── ExSwan.Crypto / CBORUtils
│   └── exswan_plug/                 # :exswan_plug (extension Hex package)
│       └── ExSwan.Plug              # Plug ceremony lifecycle
├── examples/
└── Makefile                         # monorepo orchestration
```

## Success Metrics

- Passing compatibility, rejection, property, and cryptographic tests
- Recorded browser and FIDO conformance results before a release claim
- Explicit deployment limits and storage requirements
- Clear documentation and examples
- Active community adoption

## Risk Mitigation

- Regular security reviews
- Automated testing pipeline
- Dependency vulnerability monitoring
- Community feedback integration
- Gradual feature rollout with beta testing

## Future Enhancements

- FIDO Alliance certification
- Additional attestation format support
- Advanced authenticator features
- Performance optimizations
- Mobile app integration helpers
