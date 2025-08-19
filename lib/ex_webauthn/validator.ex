defmodule ExWebauthn.Validator do
  @moduledoc """
  Validation functions for WebAuthn data structures and security requirements.

  This module provides comprehensive validation for WebAuthn operations,
  ensuring compliance with the WebAuthn specification and security best practices.
  """

  alias ExWebauthn.Assertion
  alias ExWebauthn.Attestation
  alias ExWebauthn.Credential

  @doc """
  Validates a challenge value meets WebAuthn requirements.

  Challenges must be at least 16 bytes (128 bits) of random data.

  ## Examples

      iex> ExWebauthn.Validator.validate_challenge(<<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>)
      :ok
      
      iex> ExWebauthn.Validator.validate_challenge(<<1, 2, 3>>)
      {:error, :challenge_too_short}
  """
  @spec validate_challenge(binary()) :: :ok | {:error, atom()}
  def validate_challenge(challenge) when is_binary(challenge) do
    if byte_size(challenge) >= 16 do
      :ok
    else
      {:error, :challenge_too_short}
    end
  end

  def validate_challenge(_), do: {:error, :invalid_challenge_format}

  @doc """
  Validates relying party identifier format.

  The RP ID must be a valid domain name.
  """
  @spec validate_rp_id(String.t()) :: :ok | {:error, atom()}
  def validate_rp_id(rp_id) when is_binary(rp_id) do
    # Basic domain validation - can be enhanced with more sophisticated checks
    if String.match?(
         rp_id,
         ~r/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
       ) do
      :ok
    else
      {:error, :invalid_rp_id_format}
    end
  end

  def validate_rp_id(_), do: {:error, :invalid_rp_id_format}

  @doc """
  Validates user handle requirements.

  User handles should be unique, random identifiers of at most 64 bytes.
  """
  @spec validate_user_handle(binary()) :: :ok | {:error, atom()}
  def validate_user_handle(user_handle) when is_binary(user_handle) do
    cond do
      byte_size(user_handle) == 0 ->
        {:error, :user_handle_empty}

      byte_size(user_handle) > 64 ->
        {:error, :user_handle_too_long}

      true ->
        :ok
    end
  end

  def validate_user_handle(_), do: {:error, :invalid_user_handle_format}

  @doc """
  Validates credential ID format and length.
  """
  @spec validate_credential_id(binary()) :: :ok | {:error, atom()}
  def validate_credential_id(credential_id) when is_binary(credential_id) do
    cond do
      byte_size(credential_id) == 0 ->
        {:error, :credential_id_empty}

      byte_size(credential_id) > 1023 ->
        {:error, :credential_id_too_long}

      true ->
        :ok
    end
  end

  def validate_credential_id(_), do: {:error, :invalid_credential_id_format}

  @doc """
  Validates origin against allowed origins list.
  """
  @spec validate_origin(String.t(), [String.t()]) :: :ok | {:error, atom()}
  def validate_origin(origin, allowed_origins)
      when is_binary(origin) and is_list(allowed_origins) do
    if origin in allowed_origins do
      :ok
    else
      {:error, :origin_not_allowed}
    end
  end

  def validate_origin(_, _), do: {:error, :invalid_origin_format}

  @doc """
  Validates attestation creation options structure.
  """
  @spec validate_creation_options(Attestation.CreationOptions.t()) :: :ok | {:error, atom()}
  def validate_creation_options(%Attestation.CreationOptions{} = options) do
    with :ok <- validate_challenge(options.challenge),
         :ok <- validate_rp_id(options.rp.id),
         :ok <- validate_user_handle(options.user.id),
         :ok <- validate_pub_key_cred_params(options.pub_key_cred_params) do
      :ok
    else
      error -> error
    end
  end

  def validate_creation_options(_), do: {:error, :invalid_creation_options}

  @doc """
  Validates assertion request options structure.
  """
  @spec validate_request_options(Assertion.RequestOptions.t()) :: :ok | {:error, atom()}
  def validate_request_options(%Assertion.RequestOptions{} = options) do
    with :ok <- validate_challenge(options.challenge),
         :ok <- maybe_validate_rp_id(options.rp_id) do
      :ok
    else
      error -> error
    end
  end

  def validate_request_options(_), do: {:error, :invalid_request_options}

  @doc """
  Validates public key credential parameters list.
  """
  @spec validate_pub_key_cred_params([Credential.Parameters.t()]) :: :ok | {:error, atom()}
  def validate_pub_key_cred_params(params) when is_list(params) do
    if length(params) > 0 and Enum.all?(params, &valid_credential_param?/1) do
      :ok
    else
      {:error, :invalid_pub_key_cred_params}
    end
  end

  def validate_pub_key_cred_params(_), do: {:error, :invalid_pub_key_cred_params}

  @doc """
  Validates timeout value is within acceptable range.
  """
  @spec validate_timeout(pos_integer() | nil) :: :ok | {:error, atom()}
  def validate_timeout(nil), do: :ok

  def validate_timeout(timeout) when is_integer(timeout) and timeout > 0 do
    # Timeout should be reasonable (max 5 minutes)
    if timeout <= 300_000 do
      :ok
    else
      {:error, :timeout_too_long}
    end
  end

  def validate_timeout(_), do: {:error, :invalid_timeout}

  # Private helper functions

  defp maybe_validate_rp_id(nil), do: :ok
  defp maybe_validate_rp_id(rp_id), do: validate_rp_id(rp_id)

  defp valid_credential_param?(%Credential.Parameters{type: :public_key, alg: alg})
       when is_integer(alg),
       do: true

  defp valid_credential_param?(_), do: false
end
