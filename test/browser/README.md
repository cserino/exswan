# Browser Smoke Tests

The Chromium test drives the Phoenix demo through `@simplewebauthn/browser` with a
CDP virtual CTAP2 authenticator. It performs a real ES256 registration and subsequent
authentication without reshaping options or responses.

```bash
make browser-chromium
```

Set `CHROMIUM_PATH` or `BROWSER_BASE_URL` to override local defaults. The test requires
a Chromium build with the CDP WebAuthn domain. This is a happy-path ceremony test;
prompt cancellation, replay behavior, and synchronized multi-device passkeys remain in
the manual matrix. Firefox and Safari also remain manual because this runner is built
on Chromium's CDP WebAuthn domain.
