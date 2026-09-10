defmodule RampartSAST.Isolated.Result do
  @moduledoc "Portable output from a disposable RampartSAST worker."

  @type status :: :complete | :incomplete
  @type t :: %__MODULE__{
          schema_version: pos_integer(),
          status: status(),
          inventory: map(),
          observations: [map()],
          suppressed: [map()],
          diagnostics: [map()],
          metrics: map(),
          worker: map()
        }

  @enforce_keys [
    :schema_version,
    :status,
    :inventory,
    :observations,
    :suppressed,
    :diagnostics,
    :metrics,
    :worker
  ]
  defstruct @enforce_keys

  @doc false
  @spec from_wire!(wire :: map(), worker :: map()) :: t()
  def from_wire!(%{"schema_version" => 1} = wire, worker) when is_map(worker) do
    %__MODULE__{
      schema_version: 1,
      status: parse_status!(wire["status"]),
      inventory: validate_inventory!(wire["inventory"]),
      observations: validate_maps!(wire["observations"], "observations"),
      suppressed: validate_maps!(wire["suppressed"], "suppressions"),
      diagnostics: validate_maps!(wire["diagnostics"], "diagnostics"),
      metrics: validate_map!(wire["metrics"], "metrics"),
      worker: worker
    }
  end

  def from_wire!(wire, _worker) do
    raise ArgumentError, "invalid isolated SAST result envelope: #{inspect(wire, limit: 5)}"
  end

  @doc false
  @spec failure(code :: String.t(), message :: String.t(), worker :: map()) :: t()
  def failure(code, message, worker)
      when is_binary(code) and is_binary(message) and is_map(worker) do
    %__MODULE__{
      schema_version: 1,
      status: :incomplete,
      inventory: %{
        "id" => failure_inventory_id(code, message),
        "facts" => [],
        "diagnostics" => [],
        "source_count" => 0,
        "module_owners" => %{}
      },
      observations: [],
      suppressed: [],
      diagnostics: [
        %{
          "level" => "error",
          "phase" => "isolation",
          "code" => code,
          "message" => truncate(message),
          "file" => nil,
          "rule_id" => nil
        }
      ],
      metrics: %{"source_count" => 0, "fact_count" => 0, "diagnostic_count" => 1},
      worker: worker
    }
  end

  defp parse_status!("complete"), do: :complete
  defp parse_status!("incomplete"), do: :incomplete
  defp parse_status!(_status), do: raise(ArgumentError, "invalid isolated SAST result status")

  defp validate_inventory!(
         %{
           "id" => id,
           "facts" => facts,
           "diagnostics" => diagnostics,
           "source_count" => source_count,
           "module_owners" => module_owners
         } = inventory
       )
       when is_binary(id) and is_list(facts) and is_list(diagnostics) and
              is_integer(source_count) and source_count >= 0 and is_map(module_owners) do
    if valid_entries?(facts, &valid_fact?/1) and valid_maps?(diagnostics),
      do: inventory,
      else: raise(ArgumentError, "invalid isolated SAST inventory contents")
  end

  defp validate_inventory!(_inventory) do
    raise ArgumentError, "invalid isolated SAST inventory"
  end

  defp valid_fact?(fact) when is_map(fact) do
    Enum.all?(["id", "kind", "subject", "relation", "object", "source_hash"], fn key ->
      is_binary(fact[key])
    end) and is_map(fact["span"]) and is_map(fact["attributes"])
  end

  defp valid_fact?(_fact), do: false

  defp validate_maps!(entries, _name) when is_list(entries) do
    if valid_maps?(entries),
      do: entries,
      else: raise(ArgumentError, "invalid isolated SAST result collection")
  end

  defp validate_maps!(_entries, name) do
    raise ArgumentError, "invalid isolated SAST result #{name}"
  end

  defp validate_map!(value, _name) when is_map(value), do: value
  defp validate_map!(_value, name), do: raise(ArgumentError, "invalid isolated SAST #{name}")
  defp valid_maps?(entries), do: valid_entries?(entries, &is_map/1)
  defp valid_entries?(entries, validator), do: Enum.all?(entries, validator)

  defp failure_inventory_id(code, message) do
    :sha256
    |> :crypto.hash(["isolated-failure\0", code, "\0", message])
    |> Base.encode16(case: :lower)
  end

  defp truncate(message) do
    if String.length(message) > 1_024,
      do: String.slice(message, 0, 1_024) <> "...",
      else: message
  end
end
