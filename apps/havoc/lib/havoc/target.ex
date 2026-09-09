defmodule Havoc.Target do
  @moduledoc """
  A derived in-process fuzz target.

  Providers populate the target's generator, conservative default oracles, and
  a stable locus. Execution remains caller-owned: a target describes what can
  be fuzzed, while the ExUnit property supplies the application-specific call.
  """

  @type kind :: :function | :phoenix_route | atom()
  @type t :: %__MODULE__{
          id: String.t(),
          kind: kind(),
          generator: StreamData.t(term()),
          module: module() | nil,
          function: atom() | nil,
          arity: non_neg_integer() | nil,
          parameter: term(),
          oracles: [term()],
          classes: [atom()],
          locus: map(),
          meta: map()
        }

  @enforce_keys [:id, :kind, :generator]
  defstruct [
    :id,
    :kind,
    :generator,
    :module,
    :function,
    :arity,
    :parameter,
    oracles: [:no_crash],
    classes: [],
    locus: %{},
    meta: %{}
  ]

  @doc "Runs derived targets sequentially through Havoc's normal corpus/oracle pipeline."
  @spec check_all!([t()], keyword(), (t(), term(), [term()], map() -> term())) :: :ok
  def check_all!([], _opts, _executor) do
    raise ArgumentError, "no derived Havoc targets were provided"
  end

  def check_all!(targets, opts, executor) when is_list(targets) and is_function(executor, 4) do
    Enum.each(targets, fn
      %__MODULE__{} = target -> check_target!(target, opts, executor)
      other -> raise ArgumentError, "expected a Havoc.Target, got: #{inspect(other)}"
    end)
  end

  defp check_target!(target, opts, executor) do
    base_name = Keyword.fetch!(opts, :property_name)
    base_id = Keyword.fetch!(opts, :property_id)
    declared_oracles = Keyword.get(opts, :oracles, target.oracles)
    oracle_context = Keyword.get(opts, :oracle_context, %{})

    property_opts =
      opts
      |> Keyword.put(:property_name, "#{base_name} [#{target.id}]")
      |> Keyword.put(:property_id, "#{base_id}:#{target.id}")
      |> Keyword.put(:oracles, declared_oracles)
      |> Keyword.put(:classes, merge_classes(target.classes, Keyword.get(opts, :classes, [])))
      |> Keyword.put(:locus, Map.merge(target.locus, Keyword.get(opts, :locus, %{})))

    Havoc.Property.check!(target.generator, property_opts, fn payload ->
      executor.(target, payload, declared_oracles, oracle_context)
    end)
  end

  defp merge_classes(target_classes, option_classes) do
    Enum.uniq(target_classes ++ option_classes)
  end
end
