defmodule ExWebauthn.CryptoTest do
  use ExUnit.Case
  doctest ExWebauthn.Crypto

  alias ExWebauthn.Crypto

  describe "compute_signed_data/2" do
    test "concatenates authenticator data and client data hash" do
      auth_data = <<1, 2, 3, 4, 5>>
      client_hash = <<6, 7, 8, 9, 10>>

      signed_data = Crypto.compute_signed_data(auth_data, client_hash)

      assert signed_data == <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10>>
    end
  end

  describe "verify_signature/4" do
    test "returns error for unsupported algorithm" do
      signature = :crypto.strong_rand_bytes(64)
      signed_data = :crypto.strong_rand_bytes(32)
      public_key_map = %{1 => 2, 3 => -999}

      {:error, :signature_verification_failed} =
        Crypto.verify_signature(signature, signed_data, public_key_map, -999)
    end

    test "returns error when public key is invalid" do
      signature = :crypto.strong_rand_bytes(64)
      signed_data = :crypto.strong_rand_bytes(32)
      # Missing coordinates for EC key
      public_key_map = %{1 => 2, 3 => -7}

      {:error, :signature_verification_failed} =
        Crypto.verify_signature(signature, signed_data, public_key_map, -7)
    end

    test "returns error for unsupported curve" do
      signature = :crypto.strong_rand_bytes(64)
      signed_data = :crypto.strong_rand_bytes(32)

      public_key_map = %{
        # kty: EC2
        1 => 2,
        # alg: ES256
        3 => -7,
        # unsupported curve
        -1 => 999,
        -2 => :crypto.strong_rand_bytes(32),
        -3 => :crypto.strong_rand_bytes(32)
      }

      {:error, :signature_verification_failed} =
        Crypto.verify_signature(signature, signed_data, public_key_map, -7)
    end

    # Note: Full signature verification tests would require generating actual
    # ECDSA/RSA signatures, which is complex. These tests focus on error handling.
  end

  describe "verify_signature_with_cose/4" do
    test "returns false for unsupported algorithm" do
      signature = :crypto.strong_rand_bytes(64)
      signed_data = :crypto.strong_rand_bytes(32)
      public_key_map = %{1 => 2, 3 => -999}

      assert false ==
               Crypto.verify_signature_with_cose(signed_data, signature, public_key_map, -999)
    end

    test "returns false when public key extraction fails" do
      signature = :crypto.strong_rand_bytes(64)
      signed_data = :crypto.strong_rand_bytes(32)
      # Missing coordinates
      public_key_map = %{1 => 2, 3 => -7}

      assert false ==
               Crypto.verify_signature_with_cose(signed_data, signature, public_key_map, -7)
    end

    test "returns false for unsupported curve" do
      signature = :crypto.strong_rand_bytes(64)
      signed_data = :crypto.strong_rand_bytes(32)

      public_key_map = %{
        # kty: EC2
        1 => 2,
        # unsupported curve
        -1 => 999,
        -2 => :crypto.strong_rand_bytes(32),
        -3 => :crypto.strong_rand_bytes(32)
      }

      assert false ==
               Crypto.verify_signature_with_cose(signed_data, signature, public_key_map, -7)
    end

    test "returns false for unsupported key type" do
      signature = :crypto.strong_rand_bytes(64)
      signed_data = :crypto.strong_rand_bytes(32)

      public_key_map = %{
        # unsupported kty
        1 => 999
      }

      assert false ==
               Crypto.verify_signature_with_cose(signed_data, signature, public_key_map, -7)
    end

    # Note: Actual signature verification tests would require real keys and signatures
    # These tests focus on error handling and the public API
  end
end
