defmodule ExWebauthn do
  @moduledoc """
  ExWebauthn is an Elixir library implementing the WebAuthn (FIDO2) specification
  for passwordless authentication.

  This library provides a complete implementation of the WebAuthn specification,
  enabling developers to add secure, passwordless authentication to their Elixir
  applications using FIDO2-compatible authenticators.

  ## Key Features

  - Complete WebAuthn Level 2 specification compliance
  - Registration and authentication ceremony support
  - Multiple attestation format support
  - Comprehensive validation and security checks
  - Framework integration helpers (Phoenix)

  ## Basic Usage

  The library is organized into several main modules:

  - `ExWebauthn.Registration` - Handle credential registration
  - `ExWebauthn.Authentication` - Handle credential authentication
  - `ExWebauthn.Credential` - Core credential data structures
  - `ExWebauthn.Validator` - Security validation functions

  ## Examples

  Registration flow:

      # Generate creation options
      {:ok, options} = ExWebauthn.Registration.generate_creation_options(rp, user)
      
      # Validate registration response
      {:ok, credential} = ExWebauthn.Registration.verify_creation(response, options)

  Authentication flow:

      # Generate request options
      {:ok, options} = ExWebauthn.Authentication.generate_request_options(rp_id)
      
      # Validate authentication response
      {:ok, result} = ExWebauthn.Authentication.verify_assertion(response, options, credential)
  """

  alias ExWebauthn.{Credential, Attestation, Assertion, Validator}

  @doc """
  Generates a cryptographically secure challenge for WebAuthn operations.

  Returns a 32-byte random challenge suitable for use in both registration
  and authentication ceremonies.

  ## Examples

      iex> challenge = ExWebauthn.generate_challenge()
      iex> byte_size(challenge)
      32
  """
  @spec generate_challenge() :: binary()
  def generate_challenge do
    :crypto.strong_rand_bytes(32)
  end

  @doc """
  Validates basic WebAuthn data structures.

  This is a convenience function that delegates to the appropriate
  validator based on the input type.
  """
  @spec validate(term()) :: :ok | {:error, atom()}
  def validate(%Attestation.CreationOptions{} = options) do
    Validator.validate_creation_options(options)
  end

  def validate(%Assertion.RequestOptions{} = options) do
    Validator.validate_request_options(options)
  end

  def validate(data) when is_binary(data) do
    # Only validate binary data that looks like a challenge (16+ bytes)
    if byte_size(data) >= 16 do
      Validator.validate_challenge(data)
    else
      {:error, :unsupported_validation_type}
    end
  end

  def validate(_), do: {:error, :unsupported_validation_type}

  @doc """
  Returns the library version.
  """
  @spec version() :: String.t()
  def version do
    Application.spec(:ex_webauthn, :vsn) |> to_string()
  end
end
