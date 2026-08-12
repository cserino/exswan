import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
} from "@simplewebauthn/server";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import {mkdir, writeFile} from "node:fs/promises";

const fixtureDirectory = new URL("../fixtures/", import.meta.url);
const challenge = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const credentialID = "CQgHBg";

const registration = await generateRegistrationOptions({
  rpName: "Example",
  rpID: "example.com",
  userName: "person@example.com",
  userDisplayName: "Person",
  userID: new Uint8Array([1, 2, 3, 4]),
  challenge,
  timeout: 60_000,
  attestationType: "none",
  supportedAlgorithmIDs: [-7],
});

const authentication = await generateAuthenticationOptions({
  rpID: "example.com",
  challenge,
  timeout: 60_000,
  userVerification: "preferred",
  allowCredentials: [
    {id: credentialID, transports: ["usb"]},
  ],
});

// Compilation proves that the generated objects satisfy the exact JSON types accepted
// by @simplewebauthn/browser's optionsJSON interface.
const browserRegistrationOptions: PublicKeyCredentialCreationOptionsJSON = registration;
const browserAuthenticationOptions: PublicKeyCredentialRequestOptionsJSON = authentication;

await mkdir(fixtureDirectory, {recursive: true});
await writeFile(
  new URL("options.json", fixtureDirectory),
  `${JSON.stringify(
    {
      metadata: {
        simpleWebAuthnBrowser: "13.1.2",
        simpleWebAuthnServer: "13.1.2",
      },
      inputs: {challenge, credentialID},
      registration: browserRegistrationOptions,
      authentication: browserAuthenticationOptions,
    },
    null,
    2,
  )}\n`,
);
