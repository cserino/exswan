defmodule ExSwan.Test.Authenticator do
  @moduledoc """
  A small software authenticator for application tests.

  It creates real ES256 signatures and browser-shaped registration and authentication
  responses. It is intended only for tests and must not be used to authenticate users
  in production.

  The authenticator owns one credential. Reuse it across registration and authentication
  to model a browser authenticator, or create separate values to model unknown credentials.
  """

  alias ExSwan.Credential

  @default_private_key <<
    0x42,
    0xC5,
    0x4D,
    0x91,
    0xB7,
    0x39,
    0x7A,
    0x13,
    0xE6,
    0x5A,
    0x20,
    0x8F,
    0x55,
    0x0A,
    0x62,
    0x6F,
    0x72,
    0xD1,
    0x43,
    0xD0,
    0xC4,
    0x25,
    0x95,
    0xA6,
    0x91,
    0x42,
    0xC8,
    0x09,
    0x77,
    0x60,
    0x11,
    0x2A
  >>
  @default_credential_id :binary.copy(<<0xA5>>, 32)
  @default_aaguid <<0::128>>

  @enforce_keys [:credential_id, :private_key, :public_key]
  defstruct [:credential_id, :private_key, :public_key, :user_handle]

  @type t :: %__MODULE__{
          credential_id: binary(),
          private_key: binary(),
          public_key: map(),
          user_handle: binary() | nil
        }

  @doc """
  Creates a deterministic authenticator.

  Options may replace `:credential_id`, `:user_handle`, or the 32-byte P-256
  `:private_key`. Defaults are stable so snapshots and database assertions remain simple.

      iex> authenticator = ExSwan.Test.Authenticator.new(user_handle: <<1, 2, 3>>)
      iex> byte_size(authenticator.credential_id)
      32
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    private_key = Keyword.get(opts, :private_key, @default_private_key)
    public_key = derive_public_key(private_key)

    %__MODULE__{
      credential_id: Keyword.get(opts, :credential_id, @default_credential_id),
      user_handle: Keyword.get(opts, :user_handle),
      private_key: private_key,
      public_key: public_key
    }
  end

  @doc """
  Builds a valid `none`-attestation registration response.

  Required options are `:challenge`, `:origin`, and `:rp_id`. Useful scenario controls
  include `:flags`, `:sign_count`, `:credential_id`, `:client_extensions`, and
  `:transports`.
  """
  @spec registration_response(t(), keyword()) :: map()
  def registration_response(%__MODULE__{} = authenticator, opts) do
    challenge = Keyword.fetch!(opts, :challenge)
    origin = Keyword.fetch!(opts, :origin)
    rp_id = Keyword.fetch!(opts, :rp_id)
    credential_id = Keyword.get(opts, :credential_id, authenticator.credential_id)
    flags = Keyword.get(opts, :flags, 0x45)
    sign_count = Keyword.get(opts, :sign_count, 0)
    id = encode(credential_id)
    client_data_json = client_data("webauthn.create", challenge, origin)

    auth_data =
      :crypto.hash(:sha256, rp_id) <>
        <<flags, sign_count::32-big>> <>
        Keyword.get(opts, :aaguid, @default_aaguid) <>
        <<byte_size(credential_id)::16-big>> <>
        credential_id <>
        CBOR.encode(authenticator.public_key)

    attestation_object =
      CBOR.encode(%{"fmt" => "none", "authData" => auth_data, "attStmt" => %{}})

    %{
      "id" => id,
      "rawId" => id,
      "type" => "public-key",
      "authenticatorAttachment" => Keyword.get(opts, :authenticator_attachment, "platform"),
      "clientExtensionResults" => Keyword.get(opts, :client_extensions, %{}),
      "response" => %{
        "attestationObject" => encode(attestation_object),
        "clientDataJSON" => encode(client_data_json),
        "publicKey" => encode(CBOR.encode(authenticator.public_key)),
        "publicKeyAlgorithm" => -7,
        "transports" => Keyword.get(opts, :transports, ["internal"])
      }
    }
  end

  @doc """
  Builds a valid signed authentication response.

  Required options are `:challenge`, `:origin`, and `:rp_id`. Scenario controls include
  `:flags`, `:sign_count`, `:credential_id`, and `:user_handle`. The default counter is 1.
  """
  @spec authentication_response(t(), keyword()) :: map()
  def authentication_response(%__MODULE__{} = authenticator, opts) do
    challenge = Keyword.fetch!(opts, :challenge)
    origin = Keyword.fetch!(opts, :origin)
    rp_id = Keyword.fetch!(opts, :rp_id)
    credential_id = Keyword.get(opts, :credential_id, authenticator.credential_id)
    flags = Keyword.get(opts, :flags, 0x05)
    sign_count = Keyword.get(opts, :sign_count, 1)
    client_data_json = client_data("webauthn.get", challenge, origin)
    authenticator_data = :crypto.hash(:sha256, rp_id) <> <<flags, sign_count::32-big>>
    signed_data = authenticator_data <> :crypto.hash(:sha256, client_data_json)

    signature =
      :crypto.sign(:ecdsa, :sha256, signed_data, [authenticator.private_key, :secp256r1])

    id = encode(credential_id)

    %{
      "id" => id,
      "rawId" => id,
      "type" => "public-key",
      "authenticatorAttachment" => Keyword.get(opts, :authenticator_attachment, "platform"),
      "clientExtensionResults" => Keyword.get(opts, :client_extensions, %{}),
      "response" => %{
        "clientDataJSON" => encode(client_data_json),
        "authenticatorData" => encode(authenticator_data),
        "signature" => encode(signature),
        "userHandle" =>
          encode_optional(Keyword.get(opts, :user_handle, authenticator.user_handle))
      }
    }
  end

  @doc """
  Returns the stored credential corresponding to the authenticator.

  Use `:sign_count`, `:credential_device_type`, and `:credential_backed_up` to model
  persisted state before authentication.
  """
  @spec credential(t(), keyword()) :: Credential.t()
  def credential(%__MODULE__{} = authenticator, opts \\ []) do
    %Credential{
      id: encode(authenticator.credential_id),
      public_key: CBOR.encode(authenticator.public_key),
      user_handle: Keyword.get(opts, :user_handle, authenticator.user_handle),
      sign_count: Keyword.get(opts, :sign_count, 0),
      transports: Keyword.get(opts, :transports, ["internal"]),
      credential_device_type: Keyword.get(opts, :credential_device_type, :single_device),
      credential_backed_up: Keyword.get(opts, :credential_backed_up, false)
    }
  end

  @doc """
  Corrupts a signed response without requiring callers to understand its encoding.

  Currently supported mutations are `:signature`, `:client_data`, and `:authenticator_data`.
  """
  @spec tamper(map(), :signature | :client_data | :authenticator_data) :: map()
  def tamper(response, :signature), do: put_in(response, ["response", "signature"], encode(<<0>>))

  def tamper(response, :client_data),
    do: put_in(response, ["response", "clientDataJSON"], encode("invalid json"))

  def tamper(response, :authenticator_data),
    do: put_in(response, ["response", "authenticatorData"], encode(<<0>>))

  defp derive_public_key(private_key) when byte_size(private_key) == 32 do
    {public_key, ^private_key} = :crypto.generate_key(:ecdh, :secp256r1, private_key)
    <<4, x::binary-size(32), y::binary-size(32)>> = public_key
    %{1 => 2, 3 => -7, -1 => 1, -2 => x, -3 => y}
  end

  defp client_data(type, challenge, origin) do
    Jason.encode!(%{
      "type" => type,
      "challenge" => encode(challenge),
      "origin" => origin,
      "crossOrigin" => false
    })
  end

  defp encode(value), do: Base.url_encode64(value, padding: false)
  defp encode_optional(nil), do: nil
  defp encode_optional(value), do: encode(value)
end
