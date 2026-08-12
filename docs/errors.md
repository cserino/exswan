# Public Error Reference

Public operations return `{:error, reason}`. They do not raise for malformed browser
input. Treat these reasons as server diagnostics. Do not send them unchanged to a
browser; use `ExSwan.Plug.Response` or another coarse mapping.

## Shape and option errors

- `{:missing_option, name}`: a required keyword option is absent.
- `{:missing_field, name}`: a required browser field is absent.
- `{:invalid_field, name}`: a browser field has the wrong type or value.
- `:invalid_registration_response`, `:invalid_authentication_response`,
  `:invalid_response_format`, `:invalid_assertion_response_format`,
  `:missing_required_fields`, `:missing_required_assertion_fields`: the public object
  does not have a supported browser-response shape.
- `:invalid_credential_type`, `:invalid_authenticator_attachment`,
  `:invalid_transports`, `:invalid_allow_credentials`,
  `:invalid_exclude_credentials`: a credential metadata field is invalid.

## Encoding and parser errors

- `:invalid_base64url`, `:invalid_challenge_encoding`,
  `:invalid_client_data_encoding`, `:invalid_authenticator_data_encoding`,
  `:invalid_signature_encoding`, `:invalid_credential_id_format`: a binary field is
  not strict unpadded base64url.
- `:invalid_client_data_json`: decoded client data is not valid JSON.
- `:invalid_attestation_object`, `:invalid_authenticator_data`,
  `:invalid_authenticator_data_length`, `:unexpected_authenticator_data`,
  `:invalid_credential_public_key`, `:invalid_authenticator_extensions`,
  `:missing_authenticator_extensions`, `:invalid_extensions`,
  `:missing_credential_data`: CBOR, COSE, authenticator data, or extension data is
  malformed, truncated, missing, or has trailing bytes.
- `:invalid_key_format`, `:missing_required_key_params`, `:missing_algorithm`,
  `:unsupported_key_type`, `:unsupported_curve`, `:unsupported_credential_algorithm`,
  `:invalid_public_key_algorithm`: the credential key is not a supported ES256 key.

## Protocol verification errors

- `:invalid_client_data_type`, `:challenge_mismatch`, `:origin_mismatch`,
  `:origin_not_allowed`, `:rp_id_hash_mismatch`: ceremony binding failed.
- `:credential_id_mismatch`, `:credential_algorithm_not_offered`: the response does
  not match the attested, stored, or offered credential.
- `:user_not_present`, `:user_verification_required`,
  `:invalid_user_verification_requirement`: authenticator flags do not meet policy.
- `:invalid_backup_flags`, `:credential_device_type_mismatch`: backup eligibility,
  backup state, or the stored device type is inconsistent.
- `:invalid_signature_counter`, `:signature_verification_failed`: signature or clone
  detection checks failed.
- `:user_handle_mismatch`, `:unexpected_user_handle`: the response user handle does
  not match application state.
- `:unsupported_attestation_format`: the response uses an attestation format outside
  the supported `none` surface.

## Generation validation errors

Generation can return `:challenge_too_short`, `:invalid_challenge_format`,
`:invalid_creation_options`, `:invalid_request_options`, `:invalid_rp_id_format`,
`:invalid_origin_format`, `:invalid_pub_key_cred_params`, `:invalid_timeout`,
`:timeout_too_long`, `:credential_id_empty`, `:credential_id_too_long`,
`:user_handle_empty`, `:user_handle_too_long`, or `:invalid_user_handle_format` when
server-supplied options violate their documented bounds.

## Plug lifecycle and persistence errors

`ExSwan.Plug` can also return `:registration_not_authorized`, `:ceremony_not_found`,
`:not_found`, `:expired`, `:ceremony_type_mismatch`, `:duplicate`,
`:stale_credential`, and missing-option tuples. A custom store can return an
application-specific reason; telemetry reduces non-atom reasons to `:operation_failed`
to avoid exposing callback data.
