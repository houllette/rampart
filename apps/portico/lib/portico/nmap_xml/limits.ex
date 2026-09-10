defmodule Portico.NmapXML.Limits do
  @moduledoc "Finite per-document input and decoded XML budgets, including non-collected hosts."

  @doc "Returns configurable positive limits and their defaults."
  @spec schema() :: keyword()
  def schema do
    [
      max_document_bytes: [type: :pos_integer, default: 16_777_216],
      max_depth: [type: :pos_integer, default: 64],
      max_elements: [type: :pos_integer, default: 100_000],
      max_hosts: [type: :pos_integer, default: 1_024],
      max_ports: [type: :pos_integer, default: 65_536],
      max_scripts: [type: :pos_integer, default: 16_384],
      max_script_nodes: [type: :pos_integer, default: 65_536],
      max_text_bytes: [type: :pos_integer, default: 8_388_608],
      max_scalar_bytes: [type: :pos_integer, default: 65_536]
    ]
  end

  @doc "Builds validated XML budgets from host-owned options."
  @spec new!(options :: keyword()) :: map()
  def new!(options), do: options |> NimbleOptions.validate!(schema()) |> Map.new()
end
