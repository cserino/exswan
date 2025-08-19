defmodule ExWebauthn.CryptoTest do
  use ExUnit.Case
  doctest ExWebauthn.Crypto

  alias ExWebauthn.Crypto

  describe "extract_public_key/2" do
    test "extracts EC public key for ES256" do
      x = :crypto.strong_rand_bytes(32)
      y = :crypto.strong_rand_bytes(32)

      public_key_map = %{
        # kty: EC2
        1 => 2,
        # alg: ES256
        3 => -7,
        # crv: P-256
        -1 => 1,
        # x coordinate
        -2 => x,
        # y coordinate
        -3 => y
      }

      {:ok, public_key} = Crypto.extract_public_key(public_key_map, -7)

      assert {
               {:ECPoint, <<0x04>> <> ^x <> ^y},
               {:namedCurve, :secp256r1}
             } = public_key
    end

    test "extracts EC public key for ES384" do
      x = :crypto.strong_rand_bytes(48)
      y = :crypto.strong_rand_bytes(48)

      public_key_map = %{
        # kty: EC2
        1 => 2,
        # alg: ES384
        3 => -35,
        # crv: P-384
        -1 => 2,
        # x coordinate
        -2 => x,
        # y coordinate
        -3 => y
      }

      {:ok, public_key} = Crypto.extract_public_key(public_key_map, -35)

      assert {
               {:ECPoint, <<0x04>> <> ^x <> ^y},
               {:namedCurve, :secp384r1}
             } = public_key
    end

    test "extracts RSA public key" do
      # 2048-bit key
      n = :crypto.strong_rand_bytes(256)
      # 65537
      e = <<1, 0, 1>>

      public_key_map = %{
        # kty: RSA
        1 => 3,
        # alg: RS256
        3 => -257,
        # modulus
        -1 => n,
        # exponent
        -2 => e
      }

      {:ok, public_key} = Crypto.extract_public_key(public_key_map, -257)

      n_int = :binary.decode_unsigned(n, :big)
      e_int = :binary.decode_unsigned(e, :big)

      assert {:RSAPublicKey, ^n_int, ^e_int} = public_key
    end

    test "returns error for unsupported algorithm" do
      public_key_map = %{
        1 => 2,
        # Unsupported algorithm
        3 => -999
      }

      {:error, :unsupported_algorithm} = Crypto.extract_public_key(public_key_map, -999)
    end

    test "returns error for invalid EC key" do
      # Missing y coordinate
      public_key_map = %{
        1 => 2,
        3 => -7,
        -1 => 1,
        -2 => :crypto.strong_rand_bytes(32)
        # -3 missing
      }

      {:error, :invalid_ec_public_key} = Crypto.extract_public_key(public_key_map, -7)
    end

    test "returns error for invalid RSA key" do
      # Missing exponent
      public_key_map = %{
        1 => 3,
        3 => -257,
        -1 => :crypto.strong_rand_bytes(256)
        # -2 missing
      }

      {:error, :invalid_rsa_public_key} = Crypto.extract_public_key(public_key_map, -257)
    end
  end

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

      {:error, :unsupported_algorithm} =
        Crypto.verify_signature(signature, signed_data, public_key_map, -999)
    end

    test "returns error when public key extraction fails" do
      signature = :crypto.strong_rand_bytes(64)
      signed_data = :crypto.strong_rand_bytes(32)
      # Missing coordinates
      public_key_map = %{1 => 2, 3 => -7}

      {:error, :invalid_ec_public_key} =
        Crypto.verify_signature(signature, signed_data, public_key_map, -7)
    end

    # Note: Full signature verification tests would require generating actual
    # cryptographic signatures, which is complex for unit tests. In a real
    # implementation, you'd want integration tests with known test vectors.
  end
end
