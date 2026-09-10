defmodule Havoc.Harness.Plan do
  @moduledoc """
  An inert, reviewable stateful target plan.

  A plan names operations but cannot execute them. `Havoc.Harness.Binding`
  binds the exact plan digest to host-owned callbacks after review. Payload
  references use the exact shape `%{"$payload" => ["field", ...]}`.
  """

  alias Havoc.Harness.Step

  @maximum_steps 64
  @maximum_bytes 65_536

  @type t :: %__MODULE__{
          id: String.t(),
          description: String.t(),
          steps: [Step.t()],
          meta: map(),
          sha256: String.t()
        }

  @enforce_keys [:id, :description, :steps, :meta, :sha256]
  defstruct @enforce_keys

  @doc "Builds a bounded plan from exact string-keyed JSON data."
  @spec new!(map()) :: t()
  def new!(attributes) when is_map(attributes) do
    allowed = ~w(id description steps meta)

    unless Map.keys(attributes) |> Enum.sort() == Enum.sort(allowed) do
      raise ArgumentError, "harness plan must contain exactly #{inspect(allowed)}"
    end

    id = nonempty!(attributes["id"], "plan id", 200)
    description = nonempty!(attributes["description"], "plan description", 2_000)
    meta = attributes["meta"]
    steps = attributes["steps"]

    unless is_map(meta) and json_safe?(meta),
      do: raise(ArgumentError, "plan metadata must be inert string-keyed JSON data")

    unless is_list(steps) and steps != [] and length(steps) <= @maximum_steps,
      do: raise(ArgumentError, "plan requires 1..#{@maximum_steps} steps")

    steps = Enum.map(steps, &Step.new!/1)
    ids = Enum.map(steps, & &1.id)

    unless length(ids) == length(Enum.uniq(ids)),
      do: raise(ArgumentError, "harness step IDs must be unique")

    portable = %{
      "schema_version" => 1,
      "id" => id,
      "description" => description,
      "steps" => Enum.map(steps, &Step.to_map/1),
      "meta" => meta
    }

    encoded = JSON.encode!(portable)

    if byte_size(encoded) > @maximum_bytes,
      do: raise(ArgumentError, "harness plan exceeds #{@maximum_bytes} bytes")

    %__MODULE__{
      id: id,
      description: description,
      steps: steps,
      meta: meta,
      sha256: digest(encoded)
    }
  end

  @doc "Projects the exact reviewed plan with its digest."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = plan) do
    %{
      "schema_version" => 1,
      "id" => plan.id,
      "description" => plan.description,
      "steps" => Enum.map(plan.steps, &Step.to_map/1),
      "meta" => plan.meta,
      "sha256" => plan.sha256
    }
  end

  defp nonempty!(value, _label, maximum)
       when is_binary(value) and value != "" and byte_size(value) <= maximum,
       do: value

  defp nonempty!(value, label, _maximum),
    do: raise(ArgumentError, "invalid #{label}: #{inspect(value)}")

  defp json_safe?(value)
       when is_binary(value) or is_number(value) or is_boolean(value) or is_nil(value),
       do: true

  defp json_safe?(value) when is_list(value), do: Enum.all?(value, &json_safe?/1)

  defp json_safe?(value) when is_map(value) do
    Enum.all?(value, fn {key, nested} -> is_binary(key) and json_safe?(nested) end)
  end

  defp json_safe?(_value), do: false
  defp digest(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
end
