defmodule Havoc.Harness.Step do
  @moduledoc "One inert operation in a reviewed stateful target plan."

  @type role :: :setup_control | :positive_control | :candidate | :cleanup_control | :observation
  @type t :: %__MODULE__{
          id: String.t(),
          operation: String.t(),
          role: role(),
          arguments: map()
        }

  @roles [:setup_control, :positive_control, :candidate, :cleanup_control, :observation]
  @enforce_keys [:id, :operation, :role, :arguments]
  defstruct @enforce_keys

  @doc "Builds a step from exact string-keyed JSON data without resolving an operation."
  @spec new!(map()) :: t()
  def new!(attributes) when is_map(attributes) do
    allowed = ~w(id operation role arguments)
    unknown = Map.keys(attributes) -- allowed

    unless unknown == [] and Map.keys(attributes) |> Enum.sort() == Enum.sort(allowed) do
      raise ArgumentError, "harness step must contain exactly #{inspect(allowed)}"
    end

    id = nonempty!(attributes["id"], "step id")
    operation = nonempty!(attributes["operation"], "step operation")
    role = role!(attributes["role"])
    arguments = attributes["arguments"]

    unless is_map(arguments) and json_safe?(arguments) do
      raise ArgumentError, "step arguments must be inert string-keyed JSON data"
    end

    %__MODULE__{id: id, operation: operation, role: role, arguments: arguments}
  end

  @doc "Projects the inert step without executable host state."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = step) do
    %{
      "id" => step.id,
      "operation" => step.operation,
      "role" => Atom.to_string(step.role),
      "arguments" => step.arguments
    }
  end

  defp role!(role) when is_binary(role) do
    case Enum.find(@roles, &(Atom.to_string(&1) == role)) do
      nil -> raise ArgumentError, "unsupported harness step role: #{inspect(role)}"
      value -> value
    end
  end

  defp role!(role), do: raise(ArgumentError, "invalid harness step role: #{inspect(role)}")

  defp nonempty!(value, _label) when is_binary(value) and value != "" and byte_size(value) <= 200,
    do: value

  defp nonempty!(value, label), do: raise(ArgumentError, "invalid #{label}: #{inspect(value)}")

  defp json_safe?(value)
       when is_binary(value) or is_number(value) or is_boolean(value) or is_nil(value),
       do: true

  defp json_safe?(value) when is_list(value), do: Enum.all?(value, &json_safe?/1)

  defp json_safe?(value) when is_map(value) do
    Enum.all?(value, fn {key, nested} -> is_binary(key) and json_safe?(nested) end)
  end

  defp json_safe?(_value), do: false
end
