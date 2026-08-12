defmodule ExSwan do
  @moduledoc """
  ExSwan is an Elixir library implementing the WebAuthn (FIDO2) specification
  for passwordless authentication.

  The compatibility baseline is WebAuthn Level 2 with SimpleWebAuthn browser JSON.
  Supported algorithms and attestation formats are deliberately limited to the
  combinations covered by end-to-end cryptographic tests.

  ## Key Features

  - Registration and authentication ceremony support
  - ES256 credentials and `none` attestation
  - Strict validation and security checks

  ## Basic Usage

  The four ceremony entry points are `generate_registration_options/1`,
  `verify_registration_response/1`, `generate_authentication_options/1`, and
  `verify_authentication_response/1`.
  """

  alias ExSwan.{
    Authentication,
    AuthenticationCeremony,
    Credential,
    Registration,
    RegistrationCeremony
  }

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
