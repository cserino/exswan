defmodule ExSwan.Authentication do
  @moduledoc """
  Handles WebAuthn authentication ceremony operations.

  This module provides functions for generating assertion request options,
  processing authentication responses, and verifying authentication ceremonies
  according to the WebAuthn specification.

  ## Authentication Flow

  1. Generate request options with `generate_request_options/2`
  2. Send options to client for assertion creation
  3. Receive assertion response from client
  4. Verify the response with `verify_assertion/4`
  5. Update credential counter if successful

  ## Examples

      # Generate request options
      rp_id = "example.com"
      
      {:ok, options} = ExSwan.Authentication.generate_request_options(rp_id)
      
      # After receiving assertion response from client
      {:ok, result} = ExSwan.Authentication.verify_assertion(
        response, 
        options, 
        credential, 
        origin
      )
  """

  alias ExSwan.{
    Assertion,
    Attestation,
    AuthenticationResult,
    Base64URL,
    CBORUtils,
    Common,
    Credential,
    Crypto,
    Validator
  }

  @type generate_request_options_opts :: [
          {:challenge, binary()}
          | {:timeout, pos_integer()}
          | {:allow_credentials, [Credential.Descriptor.t() | Credential.t()]}
          | {:user_verification, String.t()}
          | {:extensions, map()}
        ]

  @doc """
  Generates request options for authenticating with a credential.

  Creates properly formatted options for the `navigator.credentials.get()` call
  including challenge, relying party ID, and user verification requirements.

  ## Parameters

  - `rp_id` - Relying party identifier
  - `opts` - Optional configuration (timeout, allow_credentials, user_verification, etc.)

  ## Options

  - `:challenge` - Custom challenge (defaults to secure random 32 bytes)
  - `:timeout` - Request timeout in milliseconds (default: 60_000)
  - `:allow_credentials` - List of stored credentials or credential descriptors
  - `:user_verification` - User verification requirement ("required", "preferred", "discouraged")
  - `:extensions` - WebAuthn extensions

  ## Examples

      {:ok, options} = ExSwan.Authentication.generate_request_options("example.com")
      
      {:ok, options} = ExSwan.Authentication.generate_request_options(
        "example.com",
        allow_credentials: [credential_descriptor],
        user_verification: "required"
      )
  """
  @spec generate_request_options(String.t(), generate_request_options_opts()) ::
          {:ok, Assertion.RequestOptions.t()} | {:error, atom()}
  def generate_request_options(rp_id, opts \\ []) when is_binary(rp_id) do
    challenge = Keyword.get(opts, :challenge, :crypto.strong_rand_bytes(32))
    timeout = Keyword.get(opts, :timeout, 60_000)
    user_verification = Keyword.get(opts, :user_verification, "preferred")
    extensions = Keyword.get(opts, :extensions)

    with {:ok, allow_credentials} <-
           normalize_allow_credentials(Keyword.get(opts, :allow_credentials)) do
      request_options = %Assertion.RequestOptions{
        challenge: challenge,
        timeout: timeout,
        rp_id: rp_id,
        allow_credentials: allow_credentials,
        user_verification: user_verification,
        extensions: extensions
      }

      case Validator.validate_request_options(request_options) do
        :ok -> {:ok, request_options}
        error -> error
      end
    end
  end

  @doc """
  Verifies an authentication response and returns the verification result.

  Processes the assertion response from the client, validates the signature,
  verifies authenticator data, and checks security requirements.

  ## Parameters

  - `response` - Raw assertion response from client
  - `options` - Request options used for the authentication
  - `credential` - Stored credential to verify against
  - `origin` - Expected origin for the ceremony

  ## Returns

  - `{:ok, result}` - Successfully verified assertion with result data
  - `{:error, reason}` - Verification failure with reason

  ## Examples

      {:ok, result} = ExSwan.Authentication.verify_assertion(
        assertion_response,
        request_options,
        stored_credential,
        "https://example.com"
      )
  """
  @spec verify_assertion(
          map(),
          Assertion.RequestOptions.t(),
          Credential.t(),
          String.t() | [String.t()]
        ) :: {:ok, Assertion.Result.t()} | {:error, atom()}
  def verify_assertion(
        response,
        %Assertion.RequestOptions{} = options,
        %Credential{} = credential,
        origins
      ) do
    with {:ok, verification} <- verify_assertion_details(response, options, credential, origins) do
      {:ok, verification.legacy_result}
    end
  end

  @doc false
  @spec verify_response(map(), Credential.t(), keyword()) ::
          {:ok, AuthenticationResult.t()} | {:error, term()}
  def verify_response(response, %Credential{} = credential, opts)
      when is_map(response) and is_list(opts) do
    with {:ok, challenge} <- fetch_option(opts, :expected_challenge),
         {:ok, origin} <- fetch_option(opts, :expected_origin),
         {:ok, rp_id} <- fetch_option(opts, :expected_rp_id),
         {:ok, normalized} <- normalize_browser_response(response),
         :ok <- verify_credential_algorithm(credential),
         :ok <- verify_credential_id(normalized, credential),
         :ok <- verify_user_handle(normalized.user_handle, credential, opts),
         options <- verification_options(challenge, rp_id, opts),
         {:ok, verification} <-
           verify_assertion_details(normalized.response, options, credential, origin),
         :ok <- verify_backup_flags(verification.authenticator_data.flags),
         :ok <- verify_device_type(verification.authenticator_data.flags, credential) do
      flags = verification.authenticator_data.flags

      {:ok,
       %AuthenticationResult{
         credential_id: normalized.id,
         new_sign_count: verification.authenticator_data.sign_count,
         user_verified: flags.user_verified,
         credential_device_type: credential_device_type(flags),
         credential_backed_up: flags.backup_state,
         authenticator_extension_results: verification.authenticator_data.extensions || %{},
         client_extension_results: normalized.client_extension_results,
         authenticator_attachment: normalized.authenticator_attachment,
         user_handle: normalized.user_handle,
         origin: verification.client_data.origin,
         rp_id: rp_id
       }}
    end
  rescue
    _error in ArgumentError ->
      {:error, :invalid_authentication_response}
  end

  def verify_response(_response, _credential, _opts),
    do: {:error, :invalid_authentication_response}

  defp verify_assertion_details(response, options, credential, origins) do
    with :ok <- validate_assertion_response_structure(response),
         {:ok, client_data, client_data_json} <-
           parse_and_verify_client_data(response["clientDataJSON"], options.challenge, origins),
         {:ok, authenticator_data} <- parse_authenticator_data(response["authenticatorData"]),
         :ok <- verify_rp_id_hash(authenticator_data.rp_id_hash, options.rp_id),
         :ok <- verify_user_presence(authenticator_data),
         :ok <- verify_user_verification(authenticator_data, options.user_verification),
         # :ok <- verify_credential_id(response["credentialId"], credential.id),
         {:ok, client_data_hash} <- compute_client_data_hash(client_data_json),
         :ok <-
           verify_assertion_signature(
             response["signature"],
             response["authenticatorData"],
             client_data_hash,
             credential
           ),
         :ok <- validate_signature_counter(authenticator_data.sign_count, credential) do
      result = %Assertion.Result{
        credential_id: response["credentialId"],
        client_data_json: response["clientDataJSON"],
        authenticator_data: response["authenticatorData"],
        signature: response["signature"],
        user_handle: response["userHandle"]
      }

      {:ok,
       %{
         legacy_result: result,
         authenticator_data: authenticator_data,
         client_data: client_data
       }}
    else
      error -> error
    end
  end

  @doc """
  Converts request options to JSON-serializable format for client.

  Encodes binary data as base64url strings and formats the options
  according to WebAuthn specification requirements.
  """
  @spec options_to_json(Assertion.RequestOptions.t()) :: map()
  def options_to_json(%Assertion.RequestOptions{} = options) do
    %{
      "challenge" => Base.url_encode64(options.challenge, padding: false),
      "timeout" => options.timeout,
      "rpId" => options.rp_id,
      "allowCredentials" => format_allow_credentials(options.allow_credentials),
      "userVerification" => options.user_verification,
      "extensions" => options.extensions
    }
    |> Common.remove_nil_values()
  end

  # Private functions

  defp validate_assertion_response_structure(response) when is_map(response) do
    required_fields = ["clientDataJSON", "authenticatorData", "signature"]

    case Enum.all?(required_fields, &Map.has_key?(response, &1)) do
      true -> :ok
      false -> {:error, :missing_required_assertion_fields}
    end
  end

  defp validate_assertion_response_structure(_), do: {:error, :invalid_assertion_response_format}

  defp parse_and_verify_client_data(client_data_base64, challenge, origins)
       when is_binary(client_data_base64) do
    with {:ok, {client_data, client_data_json}} <-
           Common.parse_client_data(client_data_base64, "webauthn.get"),
         :ok <- Common.verify_challenge(client_data["challenge"], challenge),
         :ok <- Common.verify_origin(client_data["origin"], origins) do
      client_data_struct = %Assertion.ClientData{
        type: client_data["type"],
        challenge: client_data["challenge"],
        origin: client_data["origin"],
        cross_origin: client_data["crossOrigin"],
        token_binding: client_data["tokenBinding"]
      }

      {:ok, client_data_struct, client_data_json}
    end
  end

  defp parse_authenticator_data(auth_data_b64) when is_binary(auth_data_b64) do
    with {:ok, auth_data_bytes} <- Base.url_decode64(auth_data_b64, padding: false) do
      Common.parse_authenticator_data(auth_data_bytes)
    else
      _ -> {:error, :invalid_authenticator_data_encoding}
    end
  end

  defp verify_rp_id_hash(received_hash, rp_id) when is_binary(received_hash) do
    Common.verify_rp_id_hash(received_hash, rp_id)
  end

  defp verify_user_presence(authenticator_data) do
    Common.verify_user_presence(authenticator_data)
  end

  defp verify_user_verification(%Attestation.AuthenticatorData{flags: flags}, user_verification) do
    case user_verification do
      "required" ->
        if flags.user_verified do
          :ok
        else
          {:error, :user_verification_required}
        end

      _ ->
        :ok
    end
  end

  defp verify_assertion_signature(
         signature_b64,
         authenticator_data_b64,
         client_data_hash,
         credential
       ) do
    with {:ok, signature} <- decode_signature(signature_b64),
         {:ok, authenticator_data_raw} <-
           decode_authenticator_data(authenticator_data_b64),
         {:ok, public_key_map} <-
           get_credential_public_key(credential),
         {:ok, algorithm} <-
           get_signature_algorithm(public_key_map),
         signed_data <-
           Crypto.compute_signed_data(authenticator_data_raw, client_data_hash) do
      Crypto.verify_signature(signature, signed_data, public_key_map, algorithm)
    else
      error -> error
    end
  end

  defp decode_signature(signature_b64) when is_binary(signature_b64) do
    case Base.url_decode64(signature_b64, padding: false) do
      {:ok, signature} -> {:ok, signature}
      _ -> {:error, :invalid_signature_encoding}
    end
  end

  defp decode_authenticator_data(authenticator_data_b64) when is_binary(authenticator_data_b64) do
    case Base.url_decode64(authenticator_data_b64, padding: false) do
      {:ok, authenticator_data} -> {:ok, authenticator_data}
      _ -> {:error, :invalid_authenticator_data_encoding}
    end
  end

  defp get_credential_public_key(%Credential{public_key: public_key}) when is_map(public_key) do
    {:ok, public_key}
  end

  defp get_credential_public_key(%Credential{public_key: public_key})
       when is_binary(public_key) do
    CBORUtils.decode_credential_public_key(public_key)
  end

  defp get_credential_public_key(_) do
    {:error, :public_key_not_available}
  end

  defp get_signature_algorithm(public_key_map) when is_map(public_key_map) do
    case Map.get(public_key_map, 3) do
      alg when is_integer(alg) -> {:ok, alg}
      _ -> {:error, :missing_algorithm}
    end
  end

  defp validate_signature_counter(received_counter, credential)
       when is_integer(received_counter) do
    # In real implementation, we'd check against stored counter to prevent replay attacks
    # Counter should be greater than the stored counter
    stored_counter = credential.sign_count || 0

    if received_counter > stored_counter or (received_counter == 0 and stored_counter == 0) do
      :ok
    else
      {:error, :invalid_signature_counter}
    end
  end

  defp compute_client_data_hash(client_data_json) do
    Common.compute_client_data_hash(client_data_json)
  end

  defp format_allow_credentials(nil), do: nil

  defp format_allow_credentials(credentials) when is_list(credentials) do
    Enum.map(credentials, &Credential.Descriptor.to_json/1)
  end

  defp normalize_allow_credentials(nil), do: {:ok, nil}

  defp normalize_allow_credentials(credentials) when is_list(credentials) do
    credentials
    |> Enum.reduce_while({:ok, []}, fn
      %Credential.Descriptor{} = descriptor, {:ok, normalized} ->
        {:cont, {:ok, [descriptor | normalized]}}

      %Credential{id: id, transports: transports}, {:ok, normalized} when is_binary(id) ->
        descriptor = %Credential.Descriptor{
          type: :public_key,
          id: id,
          transports: transports || []
        }

        {:cont, {:ok, [descriptor | normalized]}}

      _credential, _acc ->
        {:halt, {:error, :invalid_allow_credentials}}
    end)
    |> case do
      {:ok, normalized} -> {:ok, Enum.reverse(normalized)}
      error -> error
    end
  end

  defp normalize_allow_credentials(_credentials), do: {:error, :invalid_allow_credentials}

  defp normalize_browser_response(response) do
    with {:ok, id} <- fetch_string(response, "id"),
         {:ok, raw_id} <- fetch_string(response, "rawId"),
         :ok <- verify_public_key_type(response["type"]),
         {:ok, decoded_id} <- decode_field(id, :invalid_credential_id),
         {:ok, decoded_raw_id} <- decode_field(raw_id, :invalid_raw_id),
         :ok <- verify_matching_ids(id, raw_id, decoded_id, decoded_raw_id),
         {:ok, authenticator_response} <- fetch_map(response, "response"),
         {:ok, user_handle} <- validate_browser_authenticator_response(authenticator_response),
         {:ok, client_extension_results} <- fetch_map(response, "clientExtensionResults"),
         {:ok, authenticator_attachment} <-
           validate_authenticator_attachment(response["authenticatorAttachment"]) do
      {:ok,
       %{
         id: id,
         raw_id_bytes: decoded_raw_id,
         response: %{
           "credentialId" => id,
           "clientDataJSON" => authenticator_response["clientDataJSON"],
           "authenticatorData" => authenticator_response["authenticatorData"],
           "signature" => authenticator_response["signature"],
           "userHandle" => authenticator_response["userHandle"]
         },
         user_handle: user_handle,
         client_extension_results: client_extension_results,
         authenticator_attachment: authenticator_attachment
       }}
    end
  end

  defp validate_browser_authenticator_response(response) do
    with {:ok, client_data_json} <- fetch_string(response, "clientDataJSON"),
         {:ok, authenticator_data} <- fetch_string(response, "authenticatorData"),
         {:ok, signature} <- fetch_string(response, "signature"),
         {:ok, _decoded} <- decode_field(client_data_json, :invalid_client_data_encoding),
         {:ok, _decoded} <-
           decode_field(authenticator_data, :invalid_authenticator_data_encoding),
         {:ok, decoded_signature} <- decode_field(signature, :invalid_signature_encoding),
         :ok <- require_nonempty(decoded_signature, :invalid_signature),
         {:ok, user_handle} <- decode_user_handle(response) do
      {:ok, user_handle}
    end
  end

  defp decode_user_handle(response) do
    case Map.fetch(response, "userHandle") do
      {:ok, nil} -> {:ok, nil}
      {:ok, value} -> decode_field(value, :invalid_user_handle)
      :error -> {:ok, nil}
    end
  end

  defp verify_credential_id(normalized, %Credential{id: stored_id}) do
    with {:ok, stored_id_bytes} <- decode_field(stored_id, :invalid_stored_credential_id),
         true <- stored_id == normalized.id,
         true <- stored_id_bytes == normalized.raw_id_bytes do
      :ok
    else
      false -> {:error, :credential_id_mismatch}
      {:error, _reason} = error -> error
    end
  end

  defp verify_user_handle(received, credential, opts) do
    expected = Keyword.get(opts, :expected_user_handle, credential.user_handle)

    case {received, expected} do
      {nil, _expected} -> :ok
      {value, value} when is_binary(value) -> :ok
      {_received, nil} -> {:error, :unexpected_user_handle}
      {_received, _expected} -> {:error, :user_handle_mismatch}
    end
  end

  defp verify_backup_flags(%Attestation.Flags{backup_eligible: false, backup_state: true}),
    do: {:error, :invalid_backup_flags}

  defp verify_backup_flags(%Attestation.Flags{}), do: :ok

  defp verify_device_type(_flags, %Credential{credential_device_type: nil}), do: :ok

  defp verify_device_type(flags, %Credential{credential_device_type: stored_type}) do
    if credential_device_type(flags) == stored_type do
      :ok
    else
      {:error, :credential_device_type_mismatch}
    end
  end

  defp verify_credential_algorithm(%Credential{} = credential) do
    case get_credential_public_key(credential) do
      {:ok, %{3 => -7}} -> :ok
      _other -> {:error, :unsupported_credential_algorithm}
    end
  end

  defp credential_device_type(%Attestation.Flags{backup_eligible: true}), do: :multi_device
  defp credential_device_type(%Attestation.Flags{backup_eligible: false}), do: :single_device

  defp verification_options(challenge, rp_id, opts) do
    %Assertion.RequestOptions{
      challenge: challenge,
      rp_id: rp_id,
      user_verification:
        if(Keyword.get(opts, :require_user_verification, true), do: "required", else: "preferred")
    }
  end

  defp verify_public_key_type("public-key"), do: :ok
  defp verify_public_key_type(_type), do: {:error, :invalid_credential_type}

  defp verify_matching_ids(id, raw_id, decoded_id, decoded_raw_id)
       when id == raw_id and decoded_id == decoded_raw_id,
       do: :ok

  defp verify_matching_ids(_id, _raw_id, _decoded_id, _decoded_raw_id),
    do: {:error, :credential_id_mismatch}

  defp validate_authenticator_attachment(nil), do: {:ok, nil}

  defp validate_authenticator_attachment(value) when value in ["platform", "cross-platform"],
    do: {:ok, value}

  defp validate_authenticator_attachment(_value),
    do: {:error, :invalid_authenticator_attachment}

  defp fetch_option(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:missing_option, key}}
    end
  end

  defp fetch_string(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} when is_binary(value) -> {:ok, value}
      :error -> {:error, {:missing_field, key}}
      {:ok, _value} -> {:error, {:invalid_field, key}}
    end
  end

  defp fetch_map(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} when is_map(value) -> {:ok, value}
      :error -> {:error, {:missing_field, key}}
      {:ok, _value} -> {:error, {:invalid_field, key}}
    end
  end

  defp decode_field(value, error) do
    case Base64URL.decode(value) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, :invalid_base64url} -> {:error, error}
    end
  end

  defp require_nonempty(<<>>, error), do: {:error, error}
  defp require_nonempty(_value, _error), do: :ok
end
