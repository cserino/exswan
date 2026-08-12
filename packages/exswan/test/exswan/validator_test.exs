defmodule ExSwan.ValidatorTest do
  use ExUnit.Case
  alias ExSwan.Validator

  describe "validate_challenge/1" do
    test "accepts valid challenge with minimum length" do
      challenge = :crypto.strong_rand_bytes(16)
      assert Validator.validate_challenge(challenge) == :ok
    end

    test "accepts valid challenge longer than minimum" do
      challenge = :crypto.strong_rand_bytes(32)
      assert Validator.validate_challenge(challenge) == :ok
    end

    test "rejects challenge shorter than minimum" do
      challenge = :crypto.strong_rand_bytes(15)
      assert Validator.validate_challenge(challenge) == {:error, :challenge_too_short}
    end

    test "rejects non-binary challenge" do
      assert Validator.validate_challenge("not binary") == {:error, :challenge_too_short}
      assert Validator.validate_challenge(123) == {:error, :invalid_challenge_format}
    end
  end

  describe "validate_rp_id/1" do
    test "accepts valid domain names" do
      assert Validator.validate_rp_id("example.com") == :ok
      assert Validator.validate_rp_id("sub.example.com") == :ok
      assert Validator.validate_rp_id("localhost") == :ok
    end

    test "rejects invalid domain formats" do
      assert Validator.validate_rp_id("") == {:error, :invalid_rp_id_format}
      assert Validator.validate_rp_id(".example.com") == {:error, :invalid_rp_id_format}
      assert Validator.validate_rp_id("example..com") == {:error, :invalid_rp_id_format}
    end

    test "rejects non-string input" do
      assert Validator.validate_rp_id(123) == {:error, :invalid_rp_id_format}
    end
  end

  describe "validate_user_handle/1" do
    test "accepts valid user handle" do
      user_handle = :crypto.strong_rand_bytes(32)
      assert Validator.validate_user_handle(user_handle) == :ok
    end

    test "accepts user handle at maximum length" do
      user_handle = :crypto.strong_rand_bytes(64)
      assert Validator.validate_user_handle(user_handle) == :ok
    end

    test "rejects empty user handle" do
      assert Validator.validate_user_handle(<<>>) == {:error, :user_handle_empty}
    end

    test "rejects user handle too long" do
      user_handle = :crypto.strong_rand_bytes(65)
      assert Validator.validate_user_handle(user_handle) == {:error, :user_handle_too_long}
    end

    test "rejects non-binary input" do
      assert Validator.validate_user_handle("string") == :ok
      assert Validator.validate_user_handle(123) == {:error, :invalid_user_handle_format}
    end
  end

  describe "validate_timeout/1" do
    test "accepts nil timeout" do
      assert Validator.validate_timeout(nil) == :ok
    end

    test "accepts valid timeout values" do
      assert Validator.validate_timeout(30_000) == :ok
      assert Validator.validate_timeout(120_000) == :ok
    end

    test "rejects timeout too long" do
      assert Validator.validate_timeout(400_000) == {:error, :timeout_too_long}
    end

    test "rejects zero or negative timeout" do
      assert Validator.validate_timeout(0) == {:error, :invalid_timeout}
      assert Validator.validate_timeout(-1) == {:error, :invalid_timeout}
    end

    test "rejects non-integer timeout" do
      assert Validator.validate_timeout("30000") == {:error, :invalid_timeout}
    end
  end
end
