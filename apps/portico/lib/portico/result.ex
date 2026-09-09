defmodule Portico.Result do
  @moduledoc "Versioned JSON serialization for Portico host results."

  alias Portico.Host

  @doc "Encodes a host using the stable persisted schema."
  @spec encode(Host.t()) :: {:ok, String.t()} | {:error, Jason.EncodeError.t()}
  def encode(%Host{} = host), do: Jason.encode(host)

  @doc "Encodes a host and raises on invalid metadata."
  @spec encode!(Host.t()) :: String.t()
  def encode!(%Host{} = host), do: Jason.encode!(host)

  @doc "Decodes a host persisted with a supported schema version."
  @spec decode(String.t()) :: {:ok, Host.t()} | {:error, term()}
  def decode(json) when is_binary(json) do
    with {:ok, map} <- Jason.decode(json) do
      Portico.Serialization.host_from_map(map)
    end
  end

  @doc "Returns the JSON-compatible persisted representation."
  @spec to_map(Host.t()) :: map()
  def to_map(%Host{} = host), do: Portico.Serialization.to_map(host)
end
