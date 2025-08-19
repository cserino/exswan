defmodule ExWebauthn.Authentication do
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
      
      {:ok, options} = ExWebauthn.Authentication.generate_request_options(rp_id)
      
      # After receiving assertion response from client
      {:ok, result} = ExWebauthn.Authentication.verify_assertion(
        response, 
        options, 
        credential, 
        origin
      )
  """

  import Bitwise

  alias ExWebauthn.{Assertion, Attestation, Credential, Crypto, Validator}

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
  - `:allow_credentials` - List of allowed credential descriptors
  - `:user_verification` - User verification requirement ("required", "preferred", "discouraged")
  - `:extensions` - WebAuthn extensions

  ## Examples

      {:ok, options} = ExWebauthn.Authentication.generate_request_options("example.com")
      
      {:ok, options} = ExWebauthn.Authentication.generate_request_options(
        "example.com",
        allow_credentials: [credential_descriptor],
        user_verification: "required"
      )
  """
  @spec generate_request_options(String.t(), keyword()) ::
          {:ok, Assertion.RequestOptions.t()} | {:error, atom()}
  def generate_request_options(rp_id, opts \\ []) when is_binary(rp_id) do
    challenge = Keyword.get(opts, :challenge, :crypto.strong_rand_bytes(32))
    timeout = Keyword.get(opts, :timeout, 60_000)
    allow_credentials = Keyword.get(opts, :allow_credentials)
    user_verification = Keyword.get(opts, :user_verification, "preferred")
    extensions = Keyword.get(opts, :extensions)

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

      {:ok, result} = ExWebauthn.Authentication.verify_assertion(
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
          String.t()
        ) :: {:ok, Assertion.Result.t()} | {:error, atom()}
  def verify_assertion(
        response,
        %Assertion.RequestOptions{} = options,
        %Credential{} = credential,
        origin
      ) do
    with :ok <- validate_assertion_response_structure(response),
         {:ok, _client_data} <-
           parse_and_verify_client_data(response["clientDataJSON"], options.challenge, origin),
         {:ok, authenticator_data} <- parse_authenticator_data(response["authenticatorData"]),
         :ok <- verify_rp_id_hash(authenticator_data.rp_id_hash, options.rp_id),
         :ok <- verify_user_presence(authenticator_data),
         :ok <- verify_user_verification(authenticator_data, options.user_verification),
         :ok <- verify_credential_id(response["credentialId"], credential.id),
         {:ok, client_data_hash} <- compute_client_data_hash(response["clientDataJSON"]),
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

      {:ok, result}
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
    |> remove_nil_values()
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

  defp parse_and_verify_client_data(client_data_json, challenge, origin)
       when is_binary(client_data_json) do
    with {:ok, client_data} <- Jason.decode(client_data_json),
         :ok <- verify_client_data_type(client_data["type"]),
         :ok <- verify_challenge(client_data["challenge"], challenge),
         :ok <- verify_origin(client_data["origin"], origin) do
      client_data_struct = %Assertion.ClientData{
        type: client_data["type"],
        challenge: client_data["challenge"],
        origin: client_data["origin"],
        cross_origin: client_data["crossOrigin"],
        token_binding: client_data["tokenBinding"]
      }

      {:ok, client_data_struct}
    else
      {:error, %Jason.DecodeError{}} -> {:error, :invalid_client_data_json}
      error -> error
    end
  end

  defp parse_authenticator_data(auth_data_b64) when is_binary(auth_data_b64) do
    with {:ok, auth_data_bytes} <- Base.url_decode64(auth_data_b64, padding: false) do
      if byte_size(auth_data_bytes) < 37 do
        {:error, :invalid_authenticator_data_length}
      else
        <<
          rp_id_hash::binary-size(32),
          flags::8,
          sign_count::32-big,
          _remaining::binary
        >> = auth_data_bytes

        user_present = (flags &&& 0x01) != 0
        user_verified = (flags &&& 0x04) != 0

        flags_struct = %Attestation.Flags{
          user_present: user_present,
          user_verified: user_verified,
          attested_credential_data_included: false,
          extension_data_included: (flags &&& 0x80) != 0
        }

        authenticator_data = %Attestation.AuthenticatorData{
          rp_id_hash: rp_id_hash,
          flags: flags_struct,
          sign_count: sign_count,
          attested_credential_data: nil,
          extensions: nil
        }

        {:ok, authenticator_data}
      end
    else
      _ -> {:error, :invalid_authenticator_data_encoding}
    end
  end

  defp verify_rp_id_hash(received_hash, rp_id) when is_binary(received_hash) do
    expected_hash = :crypto.hash(:sha256, rp_id)

    if received_hash == expected_hash do
      :ok
    else
      {:error, :rp_id_hash_mismatch}
    end
  end

  defp verify_user_presence(%Attestation.AuthenticatorData{flags: flags}) do
    if flags.user_present do
      :ok
    else
      {:error, :user_not_present}
    end
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

  defp verify_credential_id(received_id, expected_id) when is_binary(received_id) do
    # Decode base64url credential ID
    case Base.url_decode64(received_id, padding: false) do
      {:ok, decoded_id} ->
        if decoded_id == expected_id do
          :ok
        else
          {:error, :credential_id_mismatch}
        end

      _ ->
        {:error, :invalid_credential_id_encoding}
    end
  end

  defp verify_assertion_signature(
         signature_b64,
         authenticator_data_b64,
         client_data_hash,
         credential
       ) do
    with {:ok, signature} <- decode_signature(signature_b64),
         {:ok, authenticator_data_raw} <- decode_authenticator_data(authenticator_data_b64),
         {:ok, public_key_map} <- get_credential_public_key(credential),
         {:ok, algorithm} <- get_signature_algorithm(public_key_map),
         signed_data <- Crypto.compute_signed_data(authenticator_data_raw, client_data_hash) do
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
    hash = :crypto.hash(:sha256, client_data_json)
    {:ok, hash}
  end

  defp verify_client_data_type("webauthn.get"), do: :ok
  defp verify_client_data_type(_), do: {:error, :invalid_client_data_type}

  defp verify_challenge(received_challenge, expected_challenge)
       when is_binary(received_challenge) do
    case Base.url_decode64(received_challenge, padding: false) do
      {:ok, decoded_challenge} ->
        if decoded_challenge == expected_challenge do
          :ok
        else
          {:error, :challenge_mismatch}
        end

      _ ->
        {:error, :invalid_challenge_encoding}
    end
  end

  defp verify_origin(received_origin, expected_origin) do
    if received_origin == expected_origin do
      :ok
    else
      {:error, :origin_mismatch}
    end
  end

  defp format_allow_credentials(nil), do: nil

  defp format_allow_credentials(credentials) when is_list(credentials) do
    Enum.map(credentials, fn %Credential.Descriptor{} = desc ->
      %{
        "type" => "public-key",
        "id" => Base.url_encode64(desc.id, padding: false),
        "transports" => desc.transports
      }
    end)
  end

  defp remove_nil_values(map) when is_map(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Enum.into(%{})
  end
end
