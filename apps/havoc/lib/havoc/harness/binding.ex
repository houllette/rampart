defmodule Havoc.Harness.Binding do
  @moduledoc """
  Host-owned callbacks and limits bound to one exact inert harness plan.

  The setup, operation, and teardown callbacks are executable authority. This
  struct must never be accepted from a model, serialized into a transcript, or
  restored after resume.
  """

  alias Havoc.Harness.Plan

  @type setup :: (payload :: term() -> {:ok, state :: term()} | {:error, term()})
  @type operation ::
          (state :: term(), arguments :: map() ->
             {:ok, state :: term(), observation :: term()} | {:error, term()})
  @type teardown :: (state :: term() -> :ok | {:error, term()})

  @type t :: %__MODULE__{
          plan: Plan.t(),
          setup: setup(),
          operations: %{required(String.t()) => operation()},
          teardown: teardown(),
          max_execution_ms: pos_integer(),
          max_observation_bytes: pos_integer()
        }

  @enforce_keys [:plan, :setup, :operations, :teardown, :max_execution_ms, :max_observation_bytes]
  defstruct @enforce_keys

  @doc "Binds host callbacks only after the exact plan and operation catalog are reviewed."
  @spec new!(Plan.t(), keyword()) :: t()
  def new!(%Plan{} = plan, options) when is_list(options) do
    options =
      Keyword.validate!(options,
        setup: nil,
        operations: %{},
        teardown: nil,
        max_execution_ms: 5_000,
        max_observation_bytes: 1_048_576
      )

    setup = options[:setup]
    operations = options[:operations]
    teardown = options[:teardown]

    unless is_function(setup, 1) and is_function(teardown, 1) and is_map(operations) and
             Enum.all?(operations, fn {id, callback} ->
               is_binary(id) and id != "" and is_function(callback, 2)
             end) do
      raise ArgumentError,
            "harness binding requires setup/1, teardown/1, and string-keyed operation/2 callbacks"
    end

    required = plan.steps |> Enum.map(& &1.operation) |> MapSet.new()
    available = operations |> Map.keys() |> MapSet.new()
    missing = required |> MapSet.difference(available) |> MapSet.to_list() |> Enum.sort()

    unless missing == [],
      do:
        raise(
          ArgumentError,
          "harness binding is missing reviewed operations: #{inspect(missing)}"
        )

    validate_positive!(options[:max_execution_ms], :max_execution_ms)
    validate_positive!(options[:max_observation_bytes], :max_observation_bytes)

    %__MODULE__{
      plan: plan,
      setup: setup,
      operations: operations,
      teardown: teardown,
      max_execution_ms: options[:max_execution_ms],
      max_observation_bytes: options[:max_observation_bytes]
    }
  end

  defp validate_positive!(value, _name) when is_integer(value) and value > 0, do: :ok

  defp validate_positive!(value, name),
    do: raise(ArgumentError, "#{name} must be positive: #{inspect(value)}")
end
