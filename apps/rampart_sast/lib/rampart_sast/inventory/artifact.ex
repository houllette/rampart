defmodule RampartSAST.Inventory.Artifact do
  @moduledoc "A content-addressed, host-storable encoding of a complete static inventory."

  alias RampartSAST.Inventory

  @media_type "application/vnd.rampart.sast-inventory+erlang"

  @type t :: %__MODULE__{
          id: String.t(),
          inventory_id: String.t(),
          media_type: String.t(),
          sha256: String.t(),
          bytes: non_neg_integer(),
          payload: binary()
        }

  @enforce_keys [:id, :inventory_id, :media_type, :sha256, :bytes, :payload]
  defstruct @enforce_keys

  @doc "Encodes a complete inventory under an explicit artifact byte limit."
  @spec encode(Inventory.t(), keyword()) :: t()
  def encode(%Inventory{} = inventory, options \\ []) when is_list(options) do
    options = Keyword.validate!(options, max_bytes: 100_000_000)
    max_bytes = positive_integer!(options[:max_bytes])

    payload =
      inventory
      |> Inventory.to_map()
      |> :erlang.term_to_binary([:deterministic, :compressed])

    if byte_size(payload) > max_bytes,
      do: raise(ArgumentError, "SAST inventory artifact exceeds the configured byte limit")

    sha256 = :sha256 |> :crypto.hash(payload) |> Base.encode16(case: :lower)

    %__MODULE__{
      id: "sha256:#{sha256}",
      inventory_id: inventory.id,
      media_type: @media_type,
      sha256: sha256,
      bytes: byte_size(payload),
      payload: payload
    }
  end

  @doc "Returns artifact metadata without the potentially large payload."
  @spec manifest(t()) :: map()
  def manifest(%__MODULE__{} = artifact) do
    %{
      id: artifact.id,
      inventory_id: artifact.inventory_id,
      media_type: artifact.media_type,
      sha256: artifact.sha256,
      bytes: artifact.bytes
    }
  end

  defp positive_integer!(value) when is_integer(value) and value > 0, do: value

  defp positive_integer!(value) do
    raise ArgumentError, "SAST artifact max_bytes must be positive, got: #{inspect(value)}"
  end
end
