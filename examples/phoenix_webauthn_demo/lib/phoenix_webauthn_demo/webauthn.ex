defmodule PhoenixWebauthnDemo.WebAuthn do
  @moduledoc """
  The WebAuthn context.
  """

  import Ecto.Query, warn: false
  alias PhoenixWebauthnDemo.Repo
  alias PhoenixWebauthnDemo.Accounts.User
  alias PhoenixWebauthnDemo.WebAuthn.Credential

  @doc """
  Returns the list of credentials for a user.
  """
  def list_user_credentials(%User{id: user_id}) do
    Credential
    |> where([c], c.user_id == ^user_id)
    |> order_by([c], desc: c.last_used_at)
    |> Repo.all()
  end

  @doc """
  Gets a single credential by credential_id.
  """
  def get_credential_by_id(credential_id) when is_binary(credential_id) do
    Repo.get_by(Credential, credential_id: credential_id)
  end

  @doc """
  Creates a credential.
  """
  def create_credential(attrs \\ %{}) do
    %Credential{}
    |> Credential.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Updates a credential.
  """
  def update_credential(%Credential{} = credential, attrs) do
    credential
    |> Credential.changeset(attrs)
    |> Repo.update()
  end

  @doc """
  Deletes a credential.
  """
  def delete_credential(%Credential{} = credential) do
    Repo.delete(credential)
  end

  @doc """
  Updates credential sign count and last used time.
  """
  def update_credential_usage(%Credential{} = credential, sign_count) do
    update_credential(credential, %{
      sign_count: sign_count,
      last_used_at: DateTime.utc_now()
    })
  end

  @doc """
  Generates WebAuthn registration options for a user.
  """
  def generate_registration_options(%User{} = user) do
    rp = %ExWebauthn.Credential.RelyingParty{
      id: get_rp_id(),
      name: "Phoenix WebAuthn Demo"
    }

    webauthn_user = %ExWebauthn.Credential.User{
      id: user.user_handle,
      name: user.email,
      display_name: user.display_name || user.email
    }

    # Get existing credentials to exclude
    existing_credentials = list_user_credentials(user)

    excluded_credentials =
      for cred <- existing_credentials do
        %ExWebauthn.Credential.Descriptor{
          type: :public_key,
          id: cred.credential_id,
          transports: cred.transports
        }
      end

    case ExWebauthn.Registration.generate_creation_options(
           rp,
           webauthn_user,
           exclude_credentials: excluded_credentials
         ) do
      {:ok, options} -> {:ok, options}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Verifies a WebAuthn registration response.
  """
  def verify_registration(response, options, %User{} = user) do
    origin = get_origin()

    case ExWebauthn.Registration.verify_creation(response, options, origin) do
      {:ok, credential} ->
        # Store credential in database
        create_credential(%{
          user_id: user.id,
          credential_id: credential.id,
          public_key: :erlang.term_to_binary(credential.public_key),
          sign_count: credential.sign_count,
          backup_eligible: Map.get(credential, :backup_eligible),
          backup_state: Map.get(credential, :backup_state),
          transports: Map.get(credential, :transports, [])
        })

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Generates WebAuthn authentication options.
  """
  def generate_authentication_options(user \\ nil) do
    allowed_credentials =
      case user do
        %User{} = user ->
          user
          |> list_user_credentials()
          |> Enum.map(fn cred ->
            %ExWebauthn.Credential.Descriptor{
              type: :public_key,
              id: cred.credential_id,
              transports: cred.transports
            }
          end)

        nil ->
          []
      end

    case ExWebauthn.Authentication.generate_request_options(get_rp_id(),
           allow_credentials: allowed_credentials
         ) do
      {:ok, options} -> {:ok, options}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Verifies a WebAuthn authentication response.
  """
  def verify_authentication(%{"id" => credential_id, "response" => response}, options) do
    case get_credential_by_id(credential_id) do
      nil ->
        {:error, :credential_not_found}

      credential ->
        stored_credential = %ExWebauthn.Credential{
          type: :public_key,
          id: credential.credential_id,
          private_key: nil,
          public_key: :erlang.binary_to_term(credential.public_key),
          rp_id: get_rp_id(),
          user_handle: <<>>,
          user_display_name: "",
          cred_protect: nil,
          creation_time: credential.inserted_at || DateTime.utc_now(),
          sign_count: credential.sign_count
        }

        # Convert options map to proper RequestOptions struct
        request_options = %ExWebauthn.Assertion.RequestOptions{
          challenge: options.challenge,
          timeout: 60_000,
          rp_id: get_rp_id(),
          allow_credentials: nil,
          user_verification: "preferred",
          extensions: nil
        }

        origin = get_origin()

        case ExWebauthn.Authentication.verify_assertion(
               response,
               request_options,
               stored_credential,
               origin
             ) do
          {:ok, _result} ->
            # For now, we won't update the sign count since we need to parse authenticator data
            # TODO: Extract and update sign count from result.authenticator_data
            user = Repo.get!(User, credential.user_id)
            {:ok, user}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp get_rp_id do
    Application.get_env(:phoenix_webauthn_demo, :webauthn)[:rp_id] || "localhost"
  end

  defp get_origin do
    "http://localhost:4000"
  end
end
