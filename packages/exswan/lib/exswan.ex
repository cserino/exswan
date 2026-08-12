defmodule ExSwan do
  @moduledoc """
  ExSwan is an Elixir library implementing the WebAuthn (FIDO2) specification
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

  - `ExSwan.Registration` - Handle credential registration
  - `ExSwan.Authentication` - Handle credential authentication
  - `ExSwan.Credential` - Core credential data structures
  - `ExSwan.Validator` - Security validation functions

  ## Examples

  Registration flow:

      # Generate creation options
      {:ok, options} = ExSwan.Registration.generate_creation_options(rp, user)
      
      # Validate registration response
      {:ok, credential} = ExSwan.Registration.verify_creation(response, options, origin)

  Authentication flow:

      # Generate request options
      {:ok, options} = ExSwan.Authentication.generate_request_options(rp_id)
      
      # Validate authentication response
      {:ok, result} = ExSwan.Authentication.verify_assertion(response, options, credential)
  """

  alias ExSwan.{
    Assertion,
    Attestation,
    Authentication,
    AuthenticationCeremony,
    Credential,
    Registration,
    RegistrationCeremony,
    Validator
  }

  @doc """
  Generates a cryptographically secure challenge for WebAuthn operations.

  Returns a 32-byte random challenge suitable for use in both registration
  and authentication ceremonies.

  ## Examples

      iex> challenge = ExSwan.generate_challenge()
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
  Generates browser-ready registration options.

  The returned `:options` map can be passed directly to
  `startRegistration({optionsJSON})`. Keep `:ceremony` on the server for later
  verification.

  ## Examples

      iex> user_id = <<1, 2, 3, 4>>
      iex> {:ok, result} = ExSwan.generate_registration_options(
      ...>   rp_name: "Example",
      ...>   rp_id: "example.com",
      ...>   user_name: "person@example.com",
      ...>   user_id: user_id,
      ...>   challenge: :binary.copy(<<1>>, 32)
      ...> )
      iex> result.options["rp"]["id"]
      "example.com"
      iex> result.ceremony.user_id
      <<1, 2, 3, 4>>
  """
  @spec generate_registration_options(keyword()) ::
          {:ok, %{options: map(), ceremony: RegistrationCeremony.t()}} | {:error, term()}
  def generate_registration_options(opts) when is_list(opts) do
    with {:ok, rp_name} <- fetch_option(opts, :rp_name),
         {:ok, rp_id} <- fetch_option(opts, :rp_id),
         {:ok, user_name} <- fetch_option(opts, :user_name),
         {:ok, user_id} <- fetch_option(opts, :user_id) do
      rp = %Credential.RelyingParty{id: rp_id, name: rp_name}

      user = %Credential.User{
        id: user_id,
        name: user_name,
        display_name: Keyword.get(opts, :user_display_name, user_name)
      }

      generation_opts =
        Keyword.drop(opts, [:rp_name, :rp_id, :user_name, :user_id, :user_display_name])

      with {:ok, creation_options} <-
             Registration.generate_creation_options(rp, user, generation_opts) do
        ceremony = %RegistrationCeremony{
          challenge: creation_options.challenge,
          rp_id: rp_id,
          user_id: user_id
        }

        {:ok, %{options: Registration.options_to_json(creation_options), ceremony: ceremony}}
      end
    end
  end

  @doc """
  Convenience function for generating registration options.

  Delegates to `ExSwan.Registration.generate_creation_options/3`.
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

  Delegates to `ExSwan.Registration.verify_creation/3`.
  """
  @spec verify_registration(map(), Attestation.CreationOptions.t(), String.t()) ::
          {:ok, Credential.t()} | {:error, atom()}
  def verify_registration(response, options, origin) do
    Registration.verify_creation(response, options, origin)
  end

  @doc """
  Verifies a complete registration response from `@simplewebauthn/browser`.

  Pass the browser response without extracting its nested `response` object.

  ## Examples

      ExSwan.verify_registration_response(
        response: browser_json,
        expected_challenge: challenge,
        expected_origin: "https://example.com",
        expected_rp_id: "example.com"
      )
  """
  @spec verify_registration_response(keyword()) ::
          {:ok, ExSwan.RegistrationResult.t()} | {:error, term()}
  def verify_registration_response(opts) when is_list(opts) do
    with {:ok, response} <- fetch_option(opts, :response) do
      Registration.verify_response(response, Keyword.delete(opts, :response))
    end
  end

  @doc """
  Generates browser-ready authentication options.

  The returned `:options` map can be passed directly to
  `startAuthentication({optionsJSON})`. Keep `:ceremony` on the server for later
  verification.

  ## Examples

      iex> {:ok, result} = ExSwan.generate_authentication_options(
      ...>   rp_id: "example.com",
      ...>   challenge: :binary.copy(<<1>>, 32)
      ...> )
      iex> result.options["rpId"]
      "example.com"
      iex> result.ceremony.rp_id
      "example.com"
  """
  @spec generate_authentication_options(keyword()) ::
          {:ok, %{options: map(), ceremony: AuthenticationCeremony.t()}} | {:error, term()}
  def generate_authentication_options(opts) when is_list(opts) do
    with {:ok, rp_id} <- fetch_option(opts, :rp_id),
         generation_opts = Keyword.delete(opts, :rp_id),
         {:ok, request_options} <-
           Authentication.generate_request_options(rp_id, generation_opts) do
      ceremony = %AuthenticationCeremony{
        challenge: request_options.challenge,
        rp_id: rp_id
      }

      {:ok, %{options: Authentication.options_to_json(request_options), ceremony: ceremony}}
    end
  end

  @doc """
  Convenience function for generating authentication options.

  Delegates to `ExSwan.Authentication.generate_request_options/2`.
  """
  @spec generate_authentication_options(String.t(), keyword()) ::
          {:ok, Assertion.RequestOptions.t()} | {:error, atom()}
  def generate_authentication_options(rp_id, opts \\ []) do
    Authentication.generate_request_options(rp_id, opts)
  end

  @doc """
  Convenience function for verifying authentication responses.

  Delegates to `ExSwan.Authentication.verify_assertion/4`.
  """
  @spec verify_authentication(map(), Assertion.RequestOptions.t(), Credential.t(), String.t()) ::
          {:ok, Assertion.Result.t()} | {:error, atom()}
  def verify_authentication(response, options, credential, origin) do
    Authentication.verify_assertion(response, options, credential, origin)
  end

  @doc """
  Verifies a complete authentication response from `@simplewebauthn/browser`.

  The result includes the new signature counter and backup state that the caller must
  persist after successful verification.

  ## Examples

      ExSwan.verify_authentication_response(
        response: browser_json,
        expected_challenge: challenge,
        expected_origin: "https://example.com",
        expected_rp_id: "example.com",
        credential: stored_credential
      )
  """
  @spec verify_authentication_response(keyword()) ::
          {:ok, ExSwan.AuthenticationResult.t()} | {:error, term()}
  def verify_authentication_response(opts) when is_list(opts) do
    with {:ok, response} <- fetch_option(opts, :response),
         {:ok, credential} <- fetch_option(opts, :credential) do
      verification_opts = Keyword.drop(opts, [:response, :credential])
      Authentication.verify_response(response, credential, verification_opts)
    end
  end

  @doc """
  Convenience function for converting registration options to JSON format.

  Delegates to `ExSwan.Registration.options_to_json/1`.
  """
  @spec options_to_json(Attestation.CreationOptions.t()) :: map()
  def options_to_json(%Attestation.CreationOptions{} = options) do
    Registration.options_to_json(options)
  end

  @doc """
  Convenience function for converting authentication options to JSON format.

  Delegates to `ExSwan.Authentication.options_to_json/1`.
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
    Application.spec(:exswan, :vsn) |> to_string()
  end

  defp fetch_option(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, {:missing_option, key}}
    end
  end
end
