defmodule ExWebauthn.CBORUtilsTest do
  use ExUnit.Case, async: true

  alias ExWebauthn.CBORUtils

  describe "Firefox 117 EdDSA CBOR workaround" do
    test "should handle malformed authenticator data from Firefox 117" do
      # Reference: vendor/SimpleWebAuthn/packages/server/src/helpers/parseAuthenticatorData.test.ts:68-90
      # Firefox 117 incorrectly serializes authenticator data, using string values for kty and crv
      # See: https://github.com/duo-labs/py_webauthn/issues/175
      #      https://github.com/mozilla/authenticator-rs/pull/292

      # This is the problematic EdDSA CBOR that Firefox 117 generates:
      # Bytes decode to `{ 1: "OKP", 3: -8, -1: "Ed25519" }` (missing key -2)
      bad_eddsa_cbor = Base.decode16!("A301634F4B500327206745643235353139")

      # This should still be parseable due to our workaround
      assert {:ok, _decoded} = CBORUtils.decode_credential_public_key(bad_eddsa_cbor)

      # Verify the original data wasn't modified (important for signature verification)
      expected_bad_cbor = Base.decode16!("A301634F4B500327206745643235353139")
      assert bad_eddsa_cbor == expected_bad_cbor
    end

    test "should not modify normal CBOR data" do
      # Normal EC2 public key should not be affected by the Firefox workaround
      normal_ec2_cbor =
        CBOR.encode(%{
          # kty: EC2
          1 => 2,
          # alg: ES256
          3 => -7,
          # crv: P-256
          -1 => 1,
          # x coordinate
          -2 => :crypto.strong_rand_bytes(32),
          # y coordinate
          -3 => :crypto.strong_rand_bytes(32)
        })

      original_cbor = normal_ec2_cbor
      assert {:ok, _decoded} = CBORUtils.decode_credential_public_key(normal_ec2_cbor)

      # Should not have been modified
      assert normal_ec2_cbor == original_cbor
    end

    test "should properly parse fixed EdDSA keys" do
      # Normal EdDSA key structure (what it should look like)
      eddsa_key = %{
        # kty: OKP
        1 => 1,
        # alg: EdDSA
        3 => -8,
        # crv: Ed25519
        -1 => 6,
        # x coordinate
        -2 => :crypto.strong_rand_bytes(32)
      }

      cbor_data = CBOR.encode(eddsa_key)
      assert {:ok, decoded} = CBORUtils.decode_credential_public_key(cbor_data)

      # kty
      assert decoded[1] == 1
      # alg
      assert decoded[3] == -8
      # crv
      assert decoded[-1] == 6
      # x coordinate
      assert is_binary(decoded[-2])
    end
  end

  describe "validate_public_key/1" do
    test "validates required COSE key parameters" do
      valid_key = %{
        # kty (Key Type)
        1 => 2,
        # alg (Algorithm)
        3 => -7
      }

      assert :ok = CBORUtils.validate_public_key(valid_key)
    end

    test "rejects keys missing required parameters" do
      # Missing algorithm
      invalid_key = %{1 => 2}
      assert {:error, :missing_required_key_params} = CBORUtils.validate_public_key(invalid_key)

      # Missing key type
      invalid_key2 = %{3 => -7}
      assert {:error, :missing_required_key_params} = CBORUtils.validate_public_key(invalid_key2)
    end

    test "rejects non-map input" do
      assert {:error, :invalid_key_format} = CBORUtils.validate_public_key("not a map")
      assert {:error, :invalid_key_format} = CBORUtils.validate_public_key(123)
    end
  end

  describe "untag_decoded_cbor_data/1" do
    test "removes CBOR tags from tagged data" do
      tagged_data = %CBOR.Tag{tag: :bytes, value: "test"}
      assert "test" = CBORUtils.untag_decoded_cbor_data(tagged_data)
    end

    test "recursively removes tags from maps" do
      nested_data = %{
        "key1" => %CBOR.Tag{tag: :bytes, value: "value1"},
        "key2" => "value2"
      }

      result = CBORUtils.untag_decoded_cbor_data(nested_data)
      assert result["key1"] == "value1"
      assert result["key2"] == "value2"
    end

    test "recursively removes tags from lists" do
      list_data = [
        %CBOR.Tag{tag: :bytes, value: "item1"},
        "item2",
        %CBOR.Tag{tag: :bytes, value: "item3"}
      ]

      result = CBORUtils.untag_decoded_cbor_data(list_data)
      assert result == ["item1", "item2", "item3"]
    end

    test "leaves non-tagged data unchanged" do
      regular_data = %{"key" => "value", "number" => 42}
      assert CBORUtils.untag_decoded_cbor_data(regular_data) == regular_data
    end
  end
end
