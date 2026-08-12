defmodule ExWebauthn.Crypto do
  @moduledoc """
  Cryptographic utilities for WebAuthn operations.

  This module provides functions for signature verification, public key handling,
  and other cryptographic operations required by the WebAuthn specification.
  """

  @doc """
  Verifies a digital signature using the provided public key and data.

  ## Parameters

  - `signature` - The signature bytes to verify
  - `signed_data` - The data that was signed
  - `public_key_map` - COSE public key map from credential
  - `algorithm` - Signature algorithm identifier

  ## Returns

  - `:ok` if signature is valid
  - `{:error, reason}` if verification fails

  ## Examples

      public_key = %{1 => 2, 3 => -7, -1 => 1, -2 => x_coord, -3 => y_coord}
      {:ok} = ExWebauthn.Crypto.verify_signature(signature, data, public_key, -7)
  """
  @spec verify_signature(binary(), binary(), map(), integer()) :: :ok | {:error, atom()}
  def verify_signature(signature, signed_data, public_key_map, algorithm) do
    if verify_signature_with_cose(signed_data, signature, public_key_map, algorithm) do
      :ok
    else
      {:error, :signature_verification_failed}
    end
  end

  @doc """
  Computes the signed data for WebAuthn assertion verification.

  Concatenates authenticator data and client data hash as per WebAuthn spec.
  """
  @spec compute_signed_data(binary(), binary()) :: binary()
  def compute_signed_data(authenticator_data, client_data_hash) do
    authenticator_data <> client_data_hash
  end

  # COSE crv → OID (for EC2)
  @crv_oid %{
    # P-256 / secp256r1
    1 => {1, 2, 840, 10_045, 3, 1, 7},
    # P-384 / secp384r1
    2 => {1, 3, 132, 0, 34},
    # P-521 / secp521r1
    3 => {1, 3, 132, 0, 35}
  }

  # COSE alg → digest (and padding where needed)
  @alg_digest %{
    # ES256
    -7 => {:sha256, :ecdsa},
    # ES384
    -35 => {:sha384, :ecdsa},
    # ES512
    -36 => {:sha512, :ecdsa},
    # EdDSA (Ed25519/Ed448)
    -8 => {:none, :eddsa},
    # RS256
    -257 => {:sha256, :rsa_pkcs1},
    # PS256
    -37 => {:sha256, :rsa_pss}
  }

  # ---- Public API -----------------------------------------------------------

  @doc """
  Verify a COSE signature over `msg` using a COSE_Key map (already CBOR-decoded).
  `sig` is the signature bytes as delivered by COSE (raw r||s for ECDSA; 64B for Ed25519; PKCS#1/RSASSA-PSS for RSA).
  `alg` is the COSE alg int (e.g. -7 for ES256).
  """
  def verify_signature_with_cose(msg, sig, cose_key, alg) when is_map(cose_key) do
    case Map.get(@alg_digest, alg) do
      nil ->
        false

      {digest, kind} ->
        case cose_to_otp_pubkey(cose_key) do
          {:error, _} -> false
          pub -> verify_with_otp_key(msg, sig, pub, digest, kind)
        end
    end
  end

  defp verify_with_otp_key(msg, sig, pub, digest, kind) do
    verify_with_digest_and_kind(msg, sig, pub, digest, kind)
  rescue
    _ -> false
  catch
    _error -> false
  end

  defp verify_with_digest_and_kind(msg, sig, pub, digest, kind) do
    {sig1, opts} =
      case kind do
        :ecdsa ->
          # {p1363_to_der(sig), []}
          {sig, []}

        :eddsa ->
          {sig, []}

        :rsa_pss ->
          {sig, [rsa_padding: :rsa_pkcs1_pss_padding, rsa_mgf1_md: :sha256, rsa_pss_saltlen: 32]}

        :rsa_pkcs1 ->
          {sig, []}
      end

    case opts do
      [] -> :public_key.verify(msg, digest, sig1, pub)
      _ -> :public_key.verify(msg, digest, sig1, pub, opts)
    end
  end

  # ---- COSE → OTP public key -----------------------------------------------

  # EC2 (kty=2): needs {:ECPoint, <<0x04,x,y>>} plus {namedCurve, oid}
  defp cose_to_otp_pubkey(%{1 => 2, -1 => crv, -2 => x, -3 => y}) do
    case Map.get(@crv_oid, crv) do
      nil ->
        {:error, :unsupported_curve}

      curve_oid ->
        point = <<4, x::binary, y::binary>>
        {{:ECPoint, point}, {:namedCurve, curve_oid}}
    end
  end

  # OKP Ed25519 (kty=1): OTP wants {ed_pub, :ed25519, pub}
  defp cose_to_otp_pubkey(%{1 => 1, -1 => 6, -2 => x}) do
    {:ed_pub, :ed25519, x}
  end

  # RSA (kty=3): #'RSAPublicKey'{modulus, publicExponent}
  defp cose_to_otp_pubkey(%{1 => 3, -1 => n, -2 => e}) do
    n_int = :binary.decode_unsigned(n)
    e_int = :binary.decode_unsigned(e)
    {:RSAPublicKey, n_int, e_int}
  end

  # Fallback for unsupported key types
  defp cose_to_otp_pubkey(_), do: {:error, :unsupported_key_type}
end
