# Remaining Browser and Conformance Validation

This runbook covers the validation that cannot run in the current Linux workspace. Use
it when you can obtain a Mac, a real FIDO2 authenticator, or access to the official FIDO
Alliance conformance tool.

The work has three separate goals:

1. Prove that the unmodified demo works in current Chrome, Firefox, and Safari.
2. Prove that ExSwan works with platform, roaming, and synchronized authenticators.
3. Run the official server conformance suite against the private HTTP harness.

Do not treat one goal as proof of another. A virtual authenticator tests browser and
server integration, but it does not test Touch ID, passkey synchronization, USB, NFC,
or an authenticator vendor's firmware.

## Evidence rules

Record only the following data:

- Date and tester
- Browser name and full version
- Operating system and full version
- Authenticator category and transport
- Test case result
- A short, secret-free failure summary and issue link

Do not save credential IDs, user handles, challenges, cookies, CSRF tokens, public
keys, signatures, attestation objects, certificates, or copied completion requests.
Use copied requests only in the active test session, then discard them.

Use a new email address for each registration run. Keep the server log open, but make
sure it uses the secret-free telemetry metadata documented in [Errors](errors.md).

## Environment inventory

Try to obtain these environments. One machine can cover more than one row.

| Environment | What it proves | Minimum equipment |
| --- | --- | --- |
| Current stable Chrome | Chromium-family browser behavior | Any supported desktop OS and a platform authenticator or FIDO2 key |
| Current stable Firefox | Gecko browser behavior | Any supported desktop OS and a UV-capable FIDO2 key or supported platform authenticator |
| Current stable Safari | Shipping Safari behavior | A supported Mac; Touch ID or a compatible FIDO2 key |
| Synchronized passkey | Multi-device backup flags and user experience | Two devices on the same passkey account, such as a Mac and iPhone using the same iCloud Keychain |
| Roaming authenticator | USB or NFC interoperability | A CTAP2/FIDO2 security key that supports ES256; use a PIN-capable key when testing user verification |

For the smallest useful set, source a Touch ID Mac and one ES256-capable FIDO2 USB
key. Add a second Apple device on the same iCloud account to test a synchronized
passkey. A Windows Hello machine is useful additional coverage, but it does not replace
Safari testing.

## Prepare the demo on the browser machine

The simplest setup runs the browser and demo on the same machine. `localhost` is then a
valid WebAuthn relying-party ID and HTTP is accepted as a trustworthy local origin.

From the repository root:

```bash
cd examples/phoenix_webauthn_demo
EXSWAN_MONOREPO=true mix deps.get
EXSWAN_MONOREPO=true mix ecto.setup
EXSWAN_MONOREPO=true mix assets.setup
EXSWAN_MONOREPO=true mix assets.build
EXSWAN_MONOREPO=true mix phx.server
```

Open `http://localhost:4000` in the browser under test. Confirm that the server uses:

```text
RP ID:  localhost
Origin: http://localhost:4000
```

Use a clean browser profile when possible. Disable extensions that can intercept
requests or change page scripts.

### Test from a phone or another computer

Do not open the demo through a raw LAN address such as `http://192.168.1.20:4000`.
WebAuthn requires a trustworthy origin, and the configured RP ID must match the host.

Instead, provide a temporary HTTPS host that both devices trust. You can use a private
staging host, a trusted development certificate, or an HTTPS tunnel. Then set the exact
host and origin before you start the demo:

```bash
WEBAUTHN_RP_ID=passkey-test.example.test \
WEBAUTHN_ORIGIN=https://passkey-test.example.test \
EXSWAN_MONOREPO=true mix phx.server
```

If a proxy terminates TLS, configure it to forward to the demo and preserve the host.
Do not expose this demo as a public service. It has no rate limiting, multi-node ceremony
store, production recovery policy, or abuse controls.

## Manual browser procedure

Run every case in each target browser. Record the result in
[Browser Validation Matrix](browser-validation.md).

### 1. Registration and authentication

1. Open `/register`.
2. Enter a new email and display name.
3. Create the account and select **Create Passkey**.
4. Complete the browser prompt with the selected authenticator.
5. Confirm that the browser reaches `/dashboard`.
6. Sign out.
7. Open `/signin`.
8. Enter the same email and select the email-plus-passkey action.
9. Complete the prompt with the new credential.
10. Confirm that the browser returns to `/dashboard`.
11. Confirm that the stored credential still exists and the server reported no
    verification failure.

Expected result: registration and authentication succeed without changes to the option
or response objects. A zero signature counter is valid for authenticators that do not
implement counters, including Apple platform credentials.

Repeat authentication without an email when the browser and authenticator support a
discoverable credential. This checks the usernameless path and `userHandle` handling.

### 2. Synchronized multi-device passkey

1. Enable the platform passkey sync service on both devices.
2. Register a platform passkey on the first device.
3. Wait for the credential to synchronize.
4. Open the same HTTPS test host on the second device.
5. Authenticate with the synchronized passkey.
6. Authenticate again on the first device.

Expected result: both devices authenticate. The server accepts valid zero-counter
behavior and persists the returned backup eligibility and backup state. Record the
devices and sync service, but do not record account names.

### 3. Roaming security key

1. Register with the FIDO2 key over USB or NFC.
2. Complete PIN entry or another user-verification step when requested.
3. Sign out and authenticate with the same key.
4. If the key supports more than one transport, repeat on another supported transport.

Expected result: the ES256 credential registers and authenticates. Do not interpret a
failure from an authenticator that supports only an unadvertised algorithm as an ExSwan
regression.

### 4. Prompt cancellation

Test registration and authentication separately:

1. Start the ceremony.
2. Cancel the browser or authenticator prompt.
3. Confirm that the page shows an error and remains usable.
4. Start a new ceremony and complete it successfully.

Expected result: cancellation does not create a credential or session. The next attempt
uses new ceremony state and succeeds. Browser wording can differ, so record the error
category rather than requiring identical browser text.

### 5. One-time consumption and replay rejection

Use the browser developer tools only for this case.

1. Open the **Network** panel and preserve requests.
2. Complete a registration.
3. Find the successful `POST /api/webauthn/register/complete` request.
4. Replay that exact request once with the same session and CSRF header. Browser tools
   call this action **Edit and Resend**, **Replay XHR**, or **Copy as fetch**.
5. Confirm a `400` response with `{"error":"ceremony_unavailable"}`.
6. Discard the copied request and clear the developer-tools console.
7. Repeat the procedure for `POST /api/webauthn/authenticate/complete`.

Expected result: the first completion succeeds and the replay fails because the server
consumed the ceremony before verification.

### 6. JavaScript seam

Inspect the loaded source or the checked-in
[`webauthn.js`](../examples/phoenix_webauthn_demo/assets/js/webauthn.js). Confirm these
exact calls remain in use:

```javascript
startRegistration({optionsJSON: options})
startAuthentication({optionsJSON: options})
```

Confirm that no code converts base64url fields, renames response fields, or extracts the
nested `response` object before it sends the result to ExSwan.

## Browser result template

Add one row per browser and authenticator combination:

```text
Date:
Tester:
Browser and version:
OS and version:
Authenticator: platform | synchronized platform | USB | NFC
Authenticator model: optional, no serial number
Registration: pass | fail
Email authentication: pass | fail
Usernameless authentication: pass | fail | not supported
Cancellation recovery: pass | fail
Registration replay rejection: pass | fail
Authentication replay rejection: pass | fail
Notes or issue links:
```

## Official FIDO server conformance

The private harness is in [`test/conformance`](../test/conformance). It implements the
four HTTP endpoints used by the FIDO server tool. The official tool is not bundled with
this repository.

The FIDO Alliance provides tool access after program registration. Follow the tool's
current instructions and license terms; those instructions take precedence over this
runbook. The current program and server requirements are available from the
[FIDO Alliance server certification page](https://fidoalliance.org/certification/functional-certification/functional-certification-servers/).

### Prepare the harness

1. Use a private machine or isolated network that the conformance tool can reach.
2. Configure a trusted HTTPS endpoint if the tool runs on another machine.
3. Set `WEBAUTHN_RP_ID` to the endpoint host.
4. Set `WEBAUTHN_ORIGIN` to its exact origin.
5. Start the harness:

```bash
cd test/conformance
EXSWAN_MONOREPO=true \
WEBAUTHN_RP_ID=conformance.example.test \
WEBAUTHN_ORIGIN=https://conformance.example.test \
mix run --no-halt
```

6. Check the four endpoints from the tool machine before a full run:
   `/attestation/options`, `/attestation/result`, `/assertion/options`, and
   `/assertion/result`.
7. Select only the server profile and cases that apply to the advertised ExSwan surface:
   ES256 and `none` attestation.

Do not enable RS256, Ed25519, or another attestation format only to make a test proceed.
Those features need their own positive vectors, negative vectors, trust rules, and OTP
matrix first.

### Record and triage the run

Record the tool version, requirement profile, date, aggregate pass/fail/skip counts, and
an issue link for each failure in
[`test/conformance/results/README.md`](../test/conformance/results/README.md). Do not
commit the tool, credentials, raw protocol payloads, or tool secrets.

For each failure:

1. Reduce it to the smallest request and expected result.
2. Add a failing ExUnit test or generated compatibility fixture.
3. Confirm the test fails for the same reason as the tool.
4. Implement the protocol fix.
5. Run `make test`, `make compatibility-check`, and the private harness tests.
6. Rerun the failed official case, then rerun its full applicable section.
7. Link the regression test and rerun result from the issue.

This is the red-green loop for conformance findings. Do not patch only the HTTP harness
when the defect belongs in the core verifier.

## Automation options

| Target | Automation option | What it can prove | Main limit |
| --- | --- | --- | --- |
| Chrome/Chromium | Keep `make browser-chromium` and its CDP virtual CTAP2 authenticator in CI | Full browser-to-demo happy path | Does not test real hardware, prompt cancellation, or passkey sync |
| Firefox | Use a matched Firefox plus Marionette/geckodriver version and Mozilla's WebAuthn virtual-authenticator commands | Gecko browser-to-demo ceremonies | Validate the exact browser/driver pair before adding CI; Firefox 153 in the current workspace did not route the UV-capable ceremony to the injected authenticator |
| Firefox with hardware | Drive page navigation with WebDriver and pause for a person to touch or unlock a FIDO2 key | Shipping Firefox plus real authenticator | Semi-automated and unsuitable for unattended CI |
| Safari | Use `safaridriver` for navigation and form actions, with a person completing Touch ID or security-key prompts | Shipping Safari and real Apple UI | WebDriver cannot supply a person's biometric action; keep the run supervised |
| WebKit | Run WebKit's WebAuthn web-platform tests with its virtual-authenticator support | Engine protocol behavior | A WebKit test build is not the same evidence as shipping Safari |
| Hosted macOS or browser grid | Run the demo and WebDriver suite on a hosted Mac or vendor browser session | Repeatable browser coverage | Confirm that the service exposes WebAuthn and the required virtual or real authenticator before buying it |
| Real-device farm | Test Safari on macOS/iOS and cross-device passkeys | Shipping device behavior | Many farms do not expose biometrics, iCloud Keychain, NFC, or USB; ask for a proof run first |
| FIDO conformance | Run the licensed tool on a private, self-hosted CI worker | Repeatable official server cases | Requires FIDO access, licensed tool storage, private networking, and protected secrets |

Apple documents `safaridriver` as the supported WebDriver interface for Safari, but its
general WebDriver command list is not proof that a hosted runner can automate Touch ID.
Mozilla documents WebAuthn virtual-authenticator commands in its Marionette driver. Pin
and test the complete browser/driver pair instead of assuming any current Firefox works
with any driver. See Apple's
[Safari WebDriver guide](https://developer.apple.com/documentation/webkit/about-webdriver-for-safari),
Mozilla's
[Marionette WebAuthn API](https://firefox-source-docs.mozilla.org/python/marionette_driver.html#module-marionette_driver.webauthn),
and the WebAuthn specification's
[automation section](https://www.w3.org/TR/webauthn-2/#sctn-automation).

## Recommended order

1. Run the full manual matrix on a Touch ID Mac in Chrome, Firefox, and Safari.
2. Repeat Firefox and Safari with one ES256-capable USB security key.
3. Add a second Apple device and run the synchronized-passkey case.
4. Keep Chromium automated in pull-request CI.
5. Prototype Firefox virtual-authenticator automation in a separate, pinned CI job. Add
   it to required CI only after repeated green runs.
6. Keep Safari supervised until a tested macOS environment can complete its WebAuthn
   prompt reliably.
7. Register for the FIDO tool, run the applicable server profile, and resolve findings
   through regression tests.

After these runs, update the two remaining checkboxes in the compatibility design only
when the recorded evidence covers their full scope.
