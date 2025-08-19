defmodule ExWebauthn.CBORTest do
  use ExUnit.Case
  alias ExWebauthn.CBOR

  describe "attestation object encoding/decoding" do
    test "encodes and decodes attestation object" do
      attestation_map = %{
        "fmt" => "packed",
        "authData" => <<1, 2, 3, 4>>,
        "attStmt" => %{"alg" => -7, "sig" => <<5, 6, 7, 8>>}
      }

      {:ok, encoded} = CBOR.encode_attestation_object(attestation_map)
      {:ok, decoded} = CBOR.decode_attestation_object(encoded)

      assert decoded["fmt"] == "packed"
      assert decoded["authData"] == <<1, 2, 3, 4>>
      assert decoded["attStmt"]["alg"] == -7
      assert decoded["attStmt"]["sig"] == <<5, 6, 7, 8>>
    end

    test "validates attestation object structure" do
      valid_map = %{
        "fmt" => "packed",
        "authData" => <<1, 2, 3, 4>>,
        "attStmt" => %{}
      }

      invalid_map = %{
        "fmt" => "packed"
        # missing required fields
      }

      assert CBOR.validate_attestation_object(valid_map) == :ok
      assert CBOR.validate_attestation_object(invalid_map) == {:error, :missing_required_fields}
    end
  end

  describe "credential public key encoding/decoding" do
    test "encodes and decodes ES256 public key" do
      # ES256 public key parameters
      public_key_map = %{
        # kty (Key Type): EC2
        1 => 2,
        # alg (Algorithm): ES256
        3 => -7,
        # crv (Curve): P-256
        -1 => 1,
        # x coordinate
        -2 => <<1, 2, 3, 4>>,
        # y coordinate
        -3 => <<5, 6, 7, 8>>
      }

      {:ok, encoded} = CBOR.encode_credential_public_key(public_key_map)
      {:ok, decoded} = CBOR.decode_credential_public_key(encoded)

      # kty
      assert decoded[1] == 2
      # alg
      assert decoded[3] == -7
      # crv
      assert decoded[-1] == 1
      # x
      assert decoded[-2] == <<1, 2, 3, 4>>
      # y
      assert decoded[-3] == <<5, 6, 7, 8>>
    end

    test "validates public key structure" do
      valid_key = %{
        # kty
        1 => 2,
        # alg
        3 => -7
      }

      invalid_key = %{
        1 => 2
        # missing algorithm parameter
      }

      assert CBOR.validate_public_key(valid_key) == :ok
      assert CBOR.validate_public_key(invalid_key) == {:error, :missing_required_key_params}
      assert CBOR.validate_public_key("not a map") == {:error, :invalid_key_format}
    end
  end

  describe "extensions encoding/decoding" do
    test "encodes and decodes extensions" do
      extensions_map = %{
        "credProps" => %{"rk" => true},
        "hmac-secret" => true
      }

      {:ok, encoded} = CBOR.encode_extensions(extensions_map)
      {:ok, decoded} = CBOR.decode_extensions(encoded)

      assert decoded["credProps"]["rk"] == true
      assert decoded["hmac-secret"] == true
    end
  end
end
