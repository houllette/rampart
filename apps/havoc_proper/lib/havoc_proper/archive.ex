defmodule HavocProper.Archive do
  @moduledoc false

  use Agent

  alias Core.Seed
  alias Havoc.TermCodec

  @type entry :: {term(), [HavocProper.Coverage.line_id()], [String.t()], number()}
  @type state :: %{
          seen_lines: MapSet.t(),
          seen_features: MapSet.t(),
          entries: [entry()],
          maximum: non_neg_integer(),
          error: {atom(), term(), Exception.stacktrace()} | nil
        }

  @spec start_link(maximum :: non_neg_integer()) :: Agent.on_start()
  def start_link(maximum) do
    Agent.start_link(fn ->
      %{
        seen_lines: MapSet.new(),
        seen_features: MapSet.new(),
        entries: [],
        maximum: maximum,
        error: nil
      }
    end)
  end

  @spec observe(
          Agent.agent(),
          term(),
          [HavocProper.Coverage.line_id()],
          [String.t()],
          number()
        ) :: :ok
  def observe(agent, payload, covered_lines, features, fitness) do
    Agent.update(agent, fn state ->
      observe_sample(state, payload, covered_lines, features, fitness)
    end)
  end

  @spec record_error(Agent.agent(), atom(), term(), Exception.stacktrace()) :: :ok
  def record_error(agent, kind, reason, stacktrace) do
    Agent.update(agent, fn
      %{error: nil} = state -> %{state | error: {kind, reason, stacktrace}}
      state -> state
    end)
  end

  @spec error(Agent.agent()) :: {atom(), term(), Exception.stacktrace()} | nil
  def error(agent), do: Agent.get(agent, & &1.error)

  @spec seeds(Agent.agent(), config :: map()) :: [Seed.t()]
  def seeds(agent, config) do
    agent
    |> Agent.get(& &1.entries)
    |> Enum.reverse()
    |> Enum.map(&to_seed(&1, config))
  end

  defp observe_sample(%{maximum: 0} = state, _payload, _lines, _features, _fitness),
    do: state

  defp observe_sample(state, payload, covered_lines, features, fitness) do
    covered_set = MapSet.new(covered_lines)
    feature_set = MapSet.new(features)
    novel_lines = MapSet.difference(covered_set, state.seen_lines)
    novel_features = MapSet.difference(feature_set, state.seen_features)

    state = %{
      state
      | seen_lines: MapSet.union(state.seen_lines, covered_set),
        seen_features: MapSet.union(state.seen_features, feature_set)
    }

    if (MapSet.size(novel_lines) > 0 or MapSet.size(novel_features) > 0) and
         length(state.entries) < state.maximum do
      %{state | entries: [{payload, covered_lines, features, fitness} | state.entries]}
    else
      state
    end
  end

  defp to_seed({payload, covered_lines, features, fitness}, config) do
    %Seed{
      id:
        Core.Finding.dedupe_id(:havoc, [
          "coverage_guided",
          config.property_id,
          TermCodec.fingerprint(payload),
          TermCodec.fingerprint(covered_lines),
          TermCodec.fingerprint(features)
        ]),
      value: payload,
      classes: Enum.uniq([:coverage_guided | config.classes]),
      provenance: :generated,
      origin: nil,
      meta: %{
        property_id: config.property_id,
        property_name: config.property_name,
        coverage_fitness: length(covered_lines),
        feature_fitness: length(features),
        search_fitness: fitness,
        covered_lines: covered_lines,
        covered_features: features,
        generator: :proper_targeted
      }
    }
  end
end
