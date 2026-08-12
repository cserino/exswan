defmodule ExSwan.BinaryParserPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias ExSwan.{Base64URL, CBORUtils, Common}

  @fixture_path Path.expand(
                  "../../../../test/compatibility/fixtures/options.json",
                  __DIR__
                )

  property "strict base64url decoding round-trips arbitrary binaries" do
    check all(value <- binary(max_length: 512)) do
      encoded = Base.url_encode64(value, padding: false)
      assert Base64URL.decode(encoded) == {:ok, value}
    end
  end

  property "strict base64url decoding rejects padded encodings" do
    padded_binary =
      binary(min_length: 1, max_length: 512)
      |> filter(&(rem(byte_size(&1), 3) != 0))

    check all(value <- padded_binary) do
      padded = Base.url_encode64(value, padding: true)
      assert Base64URL.decode(padded) == {:error, :invalid_base64url}
    end
  end

  property "binary decoders return tagged results for arbitrary binaries" do
    check all(value <- binary(max_length: 512), max_runs: 500) do
      assert tagged_result?(CBORUtils.decode_attestation_object(value))
      assert tagged_result?(CBORUtils.decode_credential_public_key(value))
      assert tagged_result?(CBORUtils.decode_extensions(value))
      assert tagged_result?(Common.parse_authenticator_data(value))
    end
  end

  property "CBOR parsers reject trailing bytes" do
    check all(trailing <- binary(min_length: 1, max_length: 64)) do
      attestation = CBOR.encode(%{"fmt" => "none", "authData" => <<>>, "attStmt" => %{}})
      credential_key = CBOR.encode(%{1 => 2, 3 => -7})
      extensions = CBOR.encode(%{"credProps" => true})

      assert {:error, _reason} =
               CBORUtils.decode_attestation_object(attestation <> trailing)

      assert {:error, _reason} =
               CBORUtils.decode_credential_public_key(credential_key <> trailing)

      assert {:error, _reason} = CBORUtils.decode_extensions(extensions <> trailing)
    end
  end

  property "assertion authenticator data rejects unflagged trailing bytes" do
    check all(trailing <- binary(min_length: 1, max_length: 128)) do
      authenticator_data = <<0::256, 0x01, 0::32-big>> <> trailing

      assert Common.parse_authenticator_data(authenticator_data) ==
               {:error, :unexpected_authenticator_data}
    end
  end

  property "registration authenticator-data parsing is total over arbitrary binaries" do
    fixture = load_fixture()

    check all(authenticator_data <- binary(max_length: 512), max_runs: 500) do
      response = registration_response(fixture, authenticator_data)

      assert tagged_result?(verify_registration(fixture, response))
    end
  end

  property "registration COSE parsing is total over arbitrary binaries" do
    fixture = load_fixture()

    check all(cose_key <- binary(max_length: 256), max_runs: 500) do
      authenticator_data =
        :crypto.hash(:sha256, "example.com") <>
          <<0x45, 0::32-big, 0::128, 4::16-big, 9, 8, 7, 6>> <> cose_key

      response = registration_response(fixture, authenticator_data)

      assert tagged_result?(verify_registration(fixture, response))
    end
  end

  defp registration_response(fixture, authenticator_data) do
    attestation_object =
      CBOR.encode(%{"fmt" => "none", "authData" => authenticator_data, "attStmt" => %{}})

    put_in(
      fixture,
      ["ceremony", "registrationResponse", "response", "attestationObject"],
      Base.url_encode64(attestation_object, padding: false)
    )["ceremony"]["registrationResponse"]
  end

  defp verify_registration(fixture, response) do
    ExSwan.verify_registration_response(
      response: response,
      expected_challenge:
        Base.url_decode64!(fixture["registration"]["challenge"], padding: false),
      expected_origin: fixture["ceremony"]["origin"],
      expected_rp_id: fixture["ceremony"]["rpID"]
    )
  end

  defp load_fixture do
    @fixture_path
    |> File.read!()
    |> Jason.decode!()
  end

  defp tagged_result?({:ok, _value}), do: true
  defp tagged_result?({:error, _reason}), do: true
  defp tagged_result?(_result), do: false
end
