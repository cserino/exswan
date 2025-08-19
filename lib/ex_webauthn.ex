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
      {:ok, credential} = ExWebauthn.Registration.verify_creation(response, options, origin)

  Authentication flow:

      # Generate request options
      {:ok, options} = ExWebauthn.Authentication.generate_request_options(rp_id)
      
      # Validate authentication response
      {:ok, result} = ExWebauthn.Authentication.verify_assertion(response, options, credential)
  """

  alias ExWebauthn.{Assertion, Attestation, Authentication, Credential, Registration, Validator}

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
  Convenience function for generating registration options.

  Delegates to `ExWebauthn.Registration.generate_creation_options/3`.
  """
  @spec generate_registration_options(
          Credential.RelyingParty.t(),
          Credential.User.t(),
          keyword()
        ) :: {:ok, Attestation.CreationOptions.t()} | {:error, atom()}
  def generate_registration_options(rp, user, opts \\ []) do
    Registration.generate_creation_options(rp, user, opts)
  end

  @doc """
  Convenience function for verifying registration responses.

  Delegates to `ExWebauthn.Registration.verify_creation/3`.
  """
  @spec verify_registration(map(), Attestation.CreationOptions.t(), String.t()) ::
          {:ok, Credential.t()} | {:error, atom()}
  def verify_registration(response, options, origin) do
    Registration.verify_creation(response, options, origin)
  end

  @doc """
  Convenience function for generating authentication options.

  Delegates to `ExWebauthn.Authentication.generate_request_options/2`.
  """
  @spec generate_authentication_options(String.t(), keyword()) ::
          {:ok, Assertion.RequestOptions.t()} | {:error, atom()}
  def generate_authentication_options(rp_id, opts \\ []) do
    Authentication.generate_request_options(rp_id, opts)
  end

  @doc """
  Convenience function for verifying authentication responses.

  Delegates to `ExWebauthn.Authentication.verify_assertion/4`.
  """
  @spec verify_authentication(map(), Assertion.RequestOptions.t(), Credential.t(), String.t()) ::
          {:ok, Assertion.Result.t()} | {:error, atom()}
  def verify_authentication(response, options, credential, origin) do
    Authentication.verify_assertion(response, options, credential, origin)
  end

  @doc """
  Convenience function for converting registration options to JSON format.

  Delegates to `ExWebauthn.Registration.options_to_json/1`.
  """
  @spec options_to_json(Attestation.CreationOptions.t()) :: map()
  def options_to_json(%Attestation.CreationOptions{} = options) do
    Registration.options_to_json(options)
  end

  @doc """
  Convenience function for converting authentication options to JSON format.

  Delegates to `ExWebauthn.Authentication.options_to_json/1`.
  """
  @spec authentication_options_to_json(Assertion.RequestOptions.t()) :: map()
  def authentication_options_to_json(%Assertion.RequestOptions{} = options) do
    Authentication.options_to_json(options)
  end

  @doc """
  Returns the library version.
  """
  @spec version() :: String.t()
  def version do
    Application.spec(:ex_webauthn, :vsn) |> to_string()
  end
end
