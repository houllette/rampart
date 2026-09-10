defmodule RampartEvaluation.Historical.AshFieldPolicy do
  @moduledoc false

  alias Havoc.Observation.FieldPolicy

  @privileged_actor %{admin: true}
  @restricted_actor %{admin: false}

  def vulnerable(input) when is_map(input) do
    observation = observe(input, false)
    observation
  end

  def fixed(input) when is_map(input) do
    observation = observe(input, true)
    observation
  end

  defp observe(%{field: field, value: value} = input, authorize_aggregate_fields?) do
    FieldPolicy.new!(
      input: input,
      privileged_actor: @privileged_actor,
      restricted_actor: @restricted_actor,
      protected_fields: [field],
      paths: [
        %{
          name: :record_read,
          privileged: %{field => record_read(value, @privileged_actor)},
          restricted: %{field => record_read(value, @restricted_actor)}
        },
        %{
          name: :aggregate,
          privileged: %{
            field => aggregate_read(value, @privileged_actor, authorize_aggregate_fields?)
          },
          restricted: %{
            field => aggregate_read(value, @restricted_actor, authorize_aggregate_fields?)
          }
        }
      ],
      metadata: %{contract: :ash_field_policy, aggregate: :max}
    )
  end

  defp record_read(value, %{admin: true}), do: FieldPolicy.visible(value)
  defp record_read(_value, %{admin: false}), do: FieldPolicy.hidden()

  defp aggregate_read(value, %{admin: true}, _authorize_fields?),
    do: FieldPolicy.visible(value)

  defp aggregate_read(value, %{admin: false}, false), do: FieldPolicy.visible(value)
  defp aggregate_read(_value, %{admin: false}, true), do: FieldPolicy.hidden()
end
