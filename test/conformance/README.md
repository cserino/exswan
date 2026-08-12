# Private FIDO2 Server Conformance Harness

This harness implements the four HTTP endpoints required by the FIDO Alliance's
non-normative conformance-testing server API:

- `POST /attestation/options`
- `POST /attestation/result`
- `POST /assertion/options`
- `POST /assertion/result`

Run it only on a private test network:

```bash
EXSWAN_MONOREPO=true WEBAUTHN_RP_ID=localhost \
  WEBAUTHN_ORIGIN=http://localhost:4005 mix run --no-halt
```

The harness deliberately exposes only ExSwan's supported ES256 plus `none`
attestation surface. Tests requesting direct attestation or another algorithm fail
with the standard coarse failure envelope. Do not expand the advertised surface to
make a conformance case proceed; implement and test the missing trust rules first.

The official tool requires access granted by FIDO Alliance. Record each run in
`results/README.md`; never commit tool binaries, credentials, raw responses, public
keys, signatures, certificates, challenges, or user handles.

See
[`docs/remaining-validation.md`](../../docs/remaining-validation.md#official-fido-server-conformance)
for environment setup, run evidence, failure triage, and automation options.
