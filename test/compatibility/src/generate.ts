import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/browser";
import {mkdir, writeFile} from "node:fs/promises";
import {createHash} from "node:crypto";
import {p256} from "@noble/curves/p256";
import {Encoder} from "cbor-x";

const fixtureDirectory = new URL("../fixtures/", import.meta.url);
const challenge = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const credentialID = "CQgHBg";
const origin = "https://example.com";
const cbor = new Encoder({tagUint8Array: false, useRecords: false});

function sha256(value: Uint8Array | string): Uint8Array {
  return createHash("sha256").update(value).digest();
}

function base64url(value: Uint8Array | string): string {
  return Buffer.from(value).toString("base64url");
}

function uint32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

function concat(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((size, value) => size + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function mutateClientData<
  T extends RegistrationResponseJSON | AuthenticationResponseJSON,
>(response: T, changes: Record<string, unknown>): T {
  const mutated = structuredClone(response);
  const clientData = JSON.parse(
    Buffer.from(mutated.response.clientDataJSON, "base64url").toString("utf8"),
  ) as Record<string, unknown>;
  mutated.response.clientDataJSON = base64url(
    JSON.stringify({...clientData, ...changes}),
  );
  return mutated;
}

function mutateCredentialID<
  T extends RegistrationResponseJSON | AuthenticationResponseJSON,
>(response: T): T {
  const mutated = structuredClone(response);
  mutated.id = "AA";
  mutated.rawId = "AA";
  return mutated;
}

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

const privateKey = new Uint8Array(32);
privateKey[31] = 1;
const publicKey = p256.getPublicKey(privateKey, false);
const x = publicKey.slice(1, 33);
const y = publicKey.slice(33, 65);
const credentialIDBytes = Buffer.from(credentialID, "base64url");
const rpIDHash = sha256("example.com");
const aaguid = new Uint8Array(16);
// Canonical COSE EC2 key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
// Encode this small fixed map directly so no library-specific Map tag enters authData.
const cosePublicKey = concat(
  new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
  x,
  new Uint8Array([0x22, 0x58, 0x20]),
  y,
);
const credentialIDLength = new Uint8Array([0, credentialIDBytes.length]);
const registrationAuthenticatorData = concat(
  rpIDHash,
  new Uint8Array([0x45]), // UP, UV, and attested credential data
  uint32(0),
  aaguid,
  credentialIDLength,
  credentialIDBytes,
  cosePublicKey,
);
const registrationClientDataJSON = JSON.stringify({
  type: "webauthn.create",
  challenge: registration.challenge,
  origin,
  crossOrigin: false,
});
const attestationObject = cbor.encode({
  fmt: "none",
  authData: registrationAuthenticatorData,
  attStmt: {},
});
const registrationResponse: RegistrationResponseJSON = {
  id: credentialID,
  rawId: credentialID,
  type: "public-key",
  authenticatorAttachment: "platform",
  clientExtensionResults: {credProps: {rk: true}},
  response: {
    attestationObject: base64url(attestationObject),
    clientDataJSON: base64url(registrationClientDataJSON),
    transports: ["internal"],
    publicKeyAlgorithm: -7,
  },
};

const authenticationClientDataJSON = JSON.stringify({
  type: "webauthn.get",
  challenge: authentication.challenge,
  origin,
  crossOrigin: false,
});
const authenticationAuthenticatorData = concat(
  rpIDHash,
  new Uint8Array([0x05]), // UP and UV
  uint32(1),
);
const signedData = concat(
  authenticationAuthenticatorData,
  sha256(authenticationClientDataJSON),
);
const signature = p256.sign(sha256(signedData), privateKey).toDERRawBytes();
const authenticationResponse: AuthenticationResponseJSON = {
  id: credentialID,
  rawId: credentialID,
  type: "public-key",
  authenticatorAttachment: "platform",
  clientExtensionResults: {},
  response: {
    authenticatorData: base64url(authenticationAuthenticatorData),
    clientDataJSON: base64url(authenticationClientDataJSON),
    signature: base64url(signature),
    userHandle: base64url(new Uint8Array([1, 2, 3, 4])),
  },
};

const invalidRegistrationCases = {
  wrongChallenge: {
    response: mutateClientData(registrationResponse, {challenge: "AA"}),
    expectedError: "challenge_mismatch",
  },
  wrongOrigin: {
    response: mutateClientData(registrationResponse, {origin: "https://evil.example"}),
    expectedError: "origin_mismatch",
  },
  wrongCeremonyType: {
    response: mutateClientData(registrationResponse, {type: "webauthn.get"}),
    expectedError: "invalid_client_data_type",
  },
  wrongRpID: {
    response: registrationResponse,
    expectedRpID: "wrong.example.com",
    expectedError: "rp_id_hash_mismatch",
  },
  wrongCredentialID: {
    response: mutateCredentialID(registrationResponse),
    expectedError: "credential_id_mismatch",
  },
};

const invalidAuthenticationCases = {
  wrongChallenge: {
    response: mutateClientData(authenticationResponse, {challenge: "AA"}),
    expectedError: "challenge_mismatch",
  },
  wrongOrigin: {
    response: mutateClientData(authenticationResponse, {origin: "https://evil.example"}),
    expectedError: "origin_mismatch",
  },
  wrongCeremonyType: {
    response: mutateClientData(authenticationResponse, {type: "webauthn.create"}),
    expectedError: "invalid_client_data_type",
  },
  wrongRpID: {
    response: authenticationResponse,
    expectedRpID: "wrong.example.com",
    expectedError: "rp_id_hash_mismatch",
  },
  wrongCredentialID: {
    response: mutateCredentialID(authenticationResponse),
    expectedError: "credential_id_mismatch",
  },
};

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
      ceremony: {
        origin,
        rpID: "example.com",
        userID: "AQIDBA",
        registrationResponse,
        authenticationResponse,
        expected: {
          credentialID,
          algorithm: -7,
          registrationSignCount: 0,
          authenticationSignCount: 1,
          attestationFormat: "none",
          credentialDeviceType: "single_device",
          credentialBackedUp: false,
        },
      },
      invalid: {
        registration: invalidRegistrationCases,
        authentication: invalidAuthenticationCases,
      },
    },
    null,
    2,
  )}\n`,
);
