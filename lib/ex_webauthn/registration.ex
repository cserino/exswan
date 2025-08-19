defmodule ExWebauthn.Registration do
  import Bitwise

  @moduledoc """
  Handles WebAuthn registration ceremony operations.

  This module provides functions for generating credential creation options,
  processing attestation responses, and verifying registration ceremonies
  according to the WebAuthn specification.

  ## Registration Flow

  1. Generate creation options with `generate_creation_options/3`
  2. Send options to client for credential creation
  3. Receive attestation response from client
  4. Verify the response with `verify_creation/3`
  5. Store the resulting credential

  ## Examples

      # Generate creation options
      rp = %ExWebauthn.Credential.RelyingParty{id: "example.com", name: "Example"}
      user = %ExWebauthn.Credential.User{id: user_id, name: "user@example.com", display_name: "User"}
      
      {:ok, options} = ExWebauthn.Registration.generate_creation_options(rp, user)
      
      # After receiving attestation response from client
      {:ok, credential} = ExWebauthn.Registration.verify_creation(response, options, origin)
  """

  alias ExWebauthn.{Attestation, AttestationStatement, CBOR, Credential, Validator}

  @default_algorithms [
    # ES256
    %Credential.Parameters{type: :public_key, alg: -7},
    # ES384
    %Credential.Parameters{type: :public_key, alg: -35},
    # ES512
    %Credential.Parameters{type: :public_key, alg: -36},
    # RS256
    %Credential.Parameters{type: :public_key, alg: -257},
    # RS384
    %Credential.Parameters{type: :public_key, alg: -258},
    # RS512
    %Credential.Parameters{type: :public_key, alg: -259}
  ]

  @doc """
  Generates creation options for registering a new credential.

  Creates properly formatted options for the `navigator.credentials.create()` call
  including challenge, user information, relying party details, and algorithm preferences.

  ## Parameters

  - `rp` - Relying party information
  - `user` - User entity information  
  - `opts` - Optional configuration (timeout, exclude_credentials, etc.)

  ## Examples

      rp = %ExWebauthn.Credential.RelyingParty{id: "example.com", name: "Example Corp"}
      user = %ExWebauthn.Credential.User{
        id: :crypto.strong_rand_bytes(32),
        name: "john@example.com",
        display_name: "John Doe"
      }
      
      {:ok, options} = ExWebauthn.Registration.generate_creation_options(rp, user)
  """
  @spec generate_creation_options(
          Credential.RelyingParty.t(),
          Credential.User.t(),
          keyword()
        ) :: {:ok, Attestation.CreationOptions.t()} | {:error, atom()}
  def generate_creation_options(
        %Credential.RelyingParty{} = rp,
        %Credential.User{} = user,
        opts \\ []
      ) do
    challenge = Keyword.get(opts, :challenge, :crypto.strong_rand_bytes(32))
    timeout = Keyword.get(opts, :timeout, 60_000)
    exclude_credentials = Keyword.get(opts, :exclude_credentials)
    algorithms = Keyword.get(opts, :algorithms, @default_algorithms)
    attestation = Keyword.get(opts, :attestation, "none")
    authenticator_selection = Keyword.get(opts, :authenticator_selection)
    extensions = Keyword.get(opts, :extensions)

    creation_options = %Attestation.CreationOptions{
      rp: rp,
      user: user,
      challenge: challenge,
      pub_key_cred_params: algorithms,
      timeout: timeout,
      exclude_credentials: exclude_credentials,
      authenticator_selection: authenticator_selection,
      attestation: attestation,
      extensions: extensions
    }

    case Validator.validate_creation_options(creation_options) do
      :ok -> {:ok, creation_options}
      error -> error
    end
  end

  @doc """
  Verifies a registration response and returns a validated credential.

  Processes the attestation response from the client, validates the attestation
  statement, parses authenticator data, and extracts the credential information.

  ## Parameters

  - `response` - Raw attestation response from client
  - `options` - Creation options used for the registration
  - `origin` - Expected origin for the ceremony

  ## Returns

  - `{:ok, credential}` - Successfully validated credential
  - `{:error, reason}` - Validation failure with reason

  ## Examples

      {:ok, credential} = ExWebauthn.Registration.verify_creation(
        attestation_response,
        creation_options,
        "https://example.com"
      )
  """
  @spec verify_creation(
          map(),
          Attestation.CreationOptions.t(),
          String.t()
        ) :: {:ok, Credential.t()} | {:error, atom()}
  def verify_creation(response, %Attestation.CreationOptions{} = options, origin) do
    with :ok <- validate_response_structure(response),
         {:ok, _client_data} <-
           parse_and_verify_client_data(response["clientDataJSON"], options.challenge, origin),
         {:ok, attestation_object} <- parse_attestation_object(response["attestationObject"]),
         :ok <- verify_rp_id_hash(attestation_object["authData"], options.rp.id),
         {:ok, authenticator_data} <- parse_authenticator_data(attestation_object["authData"]),
         :ok <- verify_user_presence(authenticator_data),
         {:ok, credential_data} <- extract_credential_data(authenticator_data),
         {:ok, client_data_hash} <- compute_client_data_hash(response["clientDataJSON"]),
         :ok <-
           verify_attestation_statement(
             attestation_object,
             attestation_object["authData"],
             client_data_hash
           ) do
      credential = %Credential{
        type: :public_key,
        id: credential_data.credential_id,
        # Not stored - kept on authenticator
        private_key: nil,
        public_key: credential_data.credential_public_key,
        rp_id: options.rp.id,
        user_handle: options.user.id,
        user_display_name: options.user.display_name,
        cred_protect: nil,
        creation_time: DateTime.utc_now(),
        sign_count: authenticator_data.sign_count
      }

      {:ok, credential}
    end
  end

  @doc """
  Converts creation options to JSON-serializable format for client.

  Encodes binary data as base64url strings and formats the options
  according to WebAuthn specification requirements.
  """
  @spec options_to_json(Attestation.CreationOptions.t()) :: map()
  def options_to_json(%Attestation.CreationOptions{} = options) do
    %{
      "rp" => %{
        "id" => options.rp.id,
        "name" => options.rp.name,
        "icon" => options.rp.icon
      },
      "user" => %{
        "id" => Base.url_encode64(options.user.id, padding: false),
        "name" => options.user.name,
        "displayName" => options.user.display_name
      },
      "challenge" => Base.url_encode64(options.challenge, padding: false),
      "pubKeyCredParams" =>
        Enum.map(options.pub_key_cred_params, fn param ->
          %{
            "type" => "public-key",
            "alg" => param.alg
          }
        end),
      "timeout" => options.timeout,
      "excludeCredentials" => format_exclude_credentials(options.exclude_credentials),
      "authenticatorSelection" => format_authenticator_selection(options.authenticator_selection),
      "attestation" => options.attestation,
      "extensions" => options.extensions
    }
    |> remove_nil_values()
  end

  # Private functions

  defp validate_response_structure(response) when is_map(response) do
    required_fields = ["clientDataJSON", "attestationObject"]

    case Enum.all?(required_fields, &Map.has_key?(response, &1)) do
      true -> :ok
      false -> {:error, :missing_required_fields}
    end
  end

  defp validate_response_structure(_), do: {:error, :invalid_response_format}

  defp parse_and_verify_client_data(client_data_json, challenge, origin)
       when is_binary(client_data_json) do
    with {:ok, client_data} <- Jason.decode(client_data_json),
         :ok <- verify_client_data_type(client_data["type"]),
         :ok <- verify_challenge(client_data["challenge"], challenge),
         :ok <- verify_origin(client_data["origin"], origin) do
      {:ok, client_data}
    else
      {:error, %Jason.DecodeError{}} -> {:error, :invalid_client_data_json}
      error -> error
    end
  end

  defp parse_attestation_object(attestation_object_bytes)
       when is_binary(attestation_object_bytes) do
    case CBOR.decode_attestation_object(attestation_object_bytes) do
      {:ok, attestation_object} ->
        case CBOR.validate_attestation_object(attestation_object) do
          :ok -> {:ok, attestation_object}
          error -> error
        end

      error ->
        error
    end
  end

  defp verify_rp_id_hash(auth_data_bytes, rp_id) when is_binary(auth_data_bytes) do
    # First 32 bytes of authenticator data is RP ID hash
    <<rp_id_hash::binary-size(32), _rest::binary>> = auth_data_bytes
    expected_hash = :crypto.hash(:sha256, rp_id)

    if rp_id_hash == expected_hash do
      :ok
    else
      {:error, :rp_id_hash_mismatch}
    end
  end

  defp parse_authenticator_data(auth_data_bytes) when is_binary(auth_data_bytes) do
    # Parse authenticator data according to WebAuthn spec
    <<
      rp_id_hash::binary-size(32),
      flags::8,
      sign_count::32-big,
      remaining::binary
    >> = auth_data_bytes

    user_present = (flags &&& 0x01) != 0
    user_verified = (flags &&& 0x04) != 0
    attested_cred_data_included = (flags &&& 0x40) != 0
    extension_data_included = (flags &&& 0x80) != 0

    flags_struct = %Attestation.Flags{
      user_present: user_present,
      user_verified: user_verified,
      attested_credential_data_included: attested_cred_data_included,
      extension_data_included: extension_data_included
    }

    {attested_credential_data, extensions_data} =
      if attested_cred_data_included do
        parse_attested_credential_data(remaining, extension_data_included)
      else
        {nil, if(extension_data_included, do: remaining, else: nil)}
      end

    extensions =
      if extension_data_included and extensions_data do
        case CBOR.decode_extensions(extensions_data) do
          {:ok, ext} -> ext
          _ -> nil
        end
      else
        nil
      end

    authenticator_data = %Attestation.AuthenticatorData{
      rp_id_hash: rp_id_hash,
      flags: flags_struct,
      sign_count: sign_count,
      attested_credential_data: attested_credential_data,
      extensions: extensions
    }

    {:ok, authenticator_data}
  end

  defp parse_attested_credential_data(data, extension_data_included) do
    <<
      aaguid::binary-size(16),
      credential_id_length::16-big,
      credential_id::binary-size(credential_id_length),
      remaining::binary
    >> = data

    # Parse credential public key (CBOR-encoded COSE key)
    {credential_public_key, extensions_data} =
      if extension_data_included do
        # Need to parse CBOR to find where public key ends and extensions begin
        case CBOR.decode_credential_public_key(remaining) do
          {:ok, public_key} ->
            # Calculate size of CBOR-encoded public key
            {:ok, encoded_key} = CBOR.encode_credential_public_key(public_key)
            key_size = byte_size(encoded_key)
            <<_key::binary-size(key_size), ext_data::binary>> = remaining
            {public_key, ext_data}

          _ ->
            {%{}, remaining}
        end
      else
        case CBOR.decode_credential_public_key(remaining) do
          {:ok, public_key} -> {public_key, nil}
          _ -> {%{}, nil}
        end
      end

    attested_credential_data = %Attestation.AttestedCredentialData{
      aaguid: aaguid,
      credential_id_length: credential_id_length,
      credential_id: credential_id,
      credential_public_key: credential_public_key
    }

    {attested_credential_data, extensions_data}
  end

  defp verify_user_presence(%Attestation.AuthenticatorData{flags: flags}) do
    if flags.user_present do
      :ok
    else
      {:error, :user_not_present}
    end
  end

  defp extract_credential_data(%Attestation.AuthenticatorData{attested_credential_data: nil}) do
    {:error, :missing_credential_data}
  end

  defp extract_credential_data(%Attestation.AuthenticatorData{
         attested_credential_data: cred_data
       }) do
    {:ok, cred_data}
  end

  defp verify_attestation_statement(attestation_object, auth_data, client_data_hash) do
    fmt = attestation_object["fmt"]
    att_stmt = attestation_object["attStmt"]

    AttestationStatement.verify(fmt, att_stmt, auth_data, client_data_hash)
  end

  defp compute_client_data_hash(client_data_json) do
    hash = :crypto.hash(:sha256, client_data_json)
    {:ok, hash}
  end

  defp verify_client_data_type("webauthn.create"), do: :ok
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

  defp format_exclude_credentials(nil), do: nil

  defp format_exclude_credentials(credentials) when is_list(credentials) do
    Enum.map(credentials, fn %Credential.Descriptor{} = desc ->
      %{
        "type" => "public-key",
        "id" => Base.url_encode64(desc.id, padding: false),
        "transports" => desc.transports
      }
    end)
  end

  defp format_authenticator_selection(nil), do: nil

  defp format_authenticator_selection(%Attestation.AuthenticatorSelection{} = selection) do
    %{
      "authenticatorAttachment" => selection.authenticator_attachment,
      "residentKey" => selection.resident_key,
      "requireResidentKey" => selection.require_resident_key,
      "userVerification" => selection.user_verification
    }
    |> remove_nil_values()
  end

  defp remove_nil_values(map) when is_map(map) do
    map
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
    |> Enum.into(%{})
  end
end
