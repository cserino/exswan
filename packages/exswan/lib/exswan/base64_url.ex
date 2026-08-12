defmodule ExSwan.Base64URL do
  @moduledoc false

  @spec decode(term()) :: {:ok, binary()} | {:error, :invalid_base64url}
  def decode(value) when is_binary(value) do
    with false <- String.contains?(value, "="),
         {:ok, decoded} <- Base.url_decode64(value, padding: false),
         ^value <- Base.url_encode64(decoded, padding: false) do
      {:ok, decoded}
    else
      _ -> {:error, :invalid_base64url}
    end
  end

  def decode(_value), do: {:error, :invalid_base64url}
end
