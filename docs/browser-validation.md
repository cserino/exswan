# Browser Validation Matrix

An automated Chromium happy-path run has been recorded. The complete manual matrix is
still a release blocker if the project later decides to publish a release.

For each release candidate, test the unmodified Phoenix demo with the current stable
Chrome, Firefox, and Safari. Record the browser and operating-system versions, date,
authenticator type, and result. Do not record credential IDs, user handles,
challenges, public keys, signatures, or attestation objects.

Follow [Remaining Browser and Conformance Validation](remaining-validation.md) for
environment setup, manual steps, evidence rules, and automation options.

Each browser must pass these cases:

1. Register a new ES256 credential with `none` attestation.
2. Authenticate with the new credential and persist the new signature counter.
3. Register and authenticate a multi-device passkey when the platform supports it.
4. Reject a replay of a completed registration and authentication response.
5. Cancel each browser prompt and confirm that the application returns a stable error.
6. Confirm that the JavaScript calls use `startRegistration({optionsJSON})` and
   `startAuthentication({optionsJSON})` without response or option reshaping.

| Browser | OS | Version | Authenticator | Registration | Authentication | Date |
| --- | --- | --- | --- | --- | --- | --- |
| Chromium | Linux | 150.0.7871.128 | CDP virtual CTAP2 platform authenticator | pass (automated happy path) | pass (automated happy path) | 2026-08-12 |
| Firefox | — | — | — | not run | not run | — |
| Safari | — | — | — | not run | not run | — |

The Chromium run executes the unmodified demo JavaScript and performs a real ES256
registration followed by authentication. It does not count as evidence for prompt
cancellation, replay rejection, or a synchronized multi-device passkey. Those cases,
and the Firefox and Safari rows, remain manual because this Linux workspace has no
Safari installation and the current runner only drives Chromium's CDP WebAuthn domain.
