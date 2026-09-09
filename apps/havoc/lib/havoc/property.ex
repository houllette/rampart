defmodule Havoc.Property do
  @moduledoc """
  Executes deterministic corpus regressions before delegating random generation
  and shrinking to `StreamData.check_all/3`.
  """

  alias Havoc.Oracle.{AssertionError, Checked}
  alias Havoc.Property.Failure

  @schema [
    property_id: [type: :string, required: true],
    property_name: [type: :string, required: true],
    module: [type: :atom, required: true],
    oracles: [type: {:list, :any}, default: [:no_crash]],
    classes: [type: {:list, :atom}, default: []],
    locus: [type: :map, default: %{}],
    oracle_context: [type: :map, default: %{}],
    corpus_path: [type: {:or, [:string, nil]}, default: nil],
    replay: [type: :boolean, default: true],
    persist: [type: :boolean, default: true],
    corpus_only: [type: :boolean, default: false],
    runs: [type: :non_neg_integer, default: 200],
    max_run_time: [type: {:or, [:non_neg_integer, nil]}, default: nil],
    max_shrinking_steps: [type: :non_neg_integer, default: 100],
    max_generation_size: [type: {:or, [:non_neg_integer, nil]}, default: nil],
    initial_seed: [type: :integer]
  ]

  @doc "Runs one security property, raising `Havoc.PropertyError` on a security violation."
  @spec check!(StreamData.t(term()), keyword(), (term() -> term())) :: :ok
  def check!(generator, opts, target) when is_function(target, 1) do
    config = config!(opts)

    Core.Telemetry.span(:havoc, :property, metadata(config), fn ->
      stats = run!(generator, target, config)
      {:ok, Map.merge(metadata(config), Map.merge(stats, %{outcome: :ok, finding_count: 0}))}
    end)
  end

  @doc "Normalizes property options for alternate generation backends."
  @spec config!(opts :: keyword()) :: map()
  def config!(opts) do
    corpus_only_default = Havoc.corpus_only?()

    opts
    |> Keyword.put_new(:corpus_only, corpus_only_default)
    |> NimbleOptions.validate!(@schema)
    |> Map.new()
    |> Map.update!(:oracles, &Havoc.Oracle.normalize!/1)
  end

  @doc "Returns the stable telemetry metadata shared by property backends."
  @spec metadata(config :: map()) :: map()
  def metadata(config) do
    %{
      property_id: config.property_id,
      property_name: config.property_name,
      module: config.module
    }
  end

  defp run!(generator, target, config) do
    replayed = replay!(target, config)

    if config.corpus_only do
      %{replayed: replayed, random_runs: 0}
    else
      random_runs = random!(generator, target, config)
      %{replayed: replayed, random_runs: random_runs}
    end
  end

  @doc "Replays persisted concrete values through a normalized property config."
  @spec replay!(target :: (term() -> term()), config :: map()) :: non_neg_integer()
  def replay!(_target, %{replay: false}), do: 0

  def replay!(target, config) do
    config.property_id
    |> Havoc.Corpus.replay_values(corpus_opts(config))
    |> Enum.reduce(0, fn payload, count ->
      case evaluate(target, payload, config) do
        {:ok, _observation} -> count + 1
        {:error, failure} -> report!(failure, config)
      end
    end)
  end

  defp random!(generator, target, config) do
    counter = :counters.new(1, [])
    generator = maybe_limit_generation_size(generator, config.max_generation_size)

    result =
      StreamData.check_all(generator, stream_data_options(config), fn payload ->
        :counters.add(counter, 1, 1)

        case evaluate(target, payload, config) do
          {:ok, _observation} -> {:ok, nil}
          {:error, failure} -> {:error, failure}
        end
      end)

    case result do
      {:ok, _metadata} -> :counters.get(counter, 1)
      {:error, %{shrunk_failure: failure}} -> report!(failure, config)
    end
  end

  @doc "Evaluates one concrete payload without running a generator or emitting a finding."
  @spec evaluate(target :: (term() -> term()), payload :: term(), config :: map()) ::
          {:ok, observation :: term()} | {:error, Failure.t()}
  def evaluate(target, payload, config) do
    case invoke_target(target, payload) do
      {:ok, observation} ->
        evaluate_observation(observation, payload, config)

      {:oracle_failure, error, stacktrace} ->
        oracle_failure(error, payload, stacktrace)

      {:target_failure, kind, reason, stacktrace} ->
        exception_failure(kind, reason, stacktrace, payload, config)
    end
  end

  defp invoke_target(target, payload) do
    {:ok, target.(payload)}
  rescue
    error in AssertionError -> {:oracle_failure, error, __STACKTRACE__}
    error -> {:target_failure, :error, error, __STACKTRACE__}
  catch
    kind, reason -> {:target_failure, kind, reason, __STACKTRACE__}
  end

  defp evaluate_observation(%Checked{observation: observation}, _payload, _config) do
    {:ok, observation}
  end

  defp evaluate_observation(observation, payload, config) do
    config.oracles
    |> Havoc.Oracle.check_normalized(observation, payload, config.oracle_context)
    |> oracle_result(observation, payload)
  rescue
    error -> test_exception(error, :error, __STACKTRACE__, payload)
  catch
    kind, reason -> test_exception(reason, kind, __STACKTRACE__, payload)
  end

  defp oracle_result(:ok, observation, _payload), do: {:ok, observation}

  defp oracle_result({:error, violations}, observation, payload) do
    {:error,
     %Failure{
       kind: :violation,
       payload: payload,
       observation: observation,
       violations: violations
     }}
  end

  defp oracle_failure(error, payload, stacktrace) do
    {:error,
     %Failure{
       kind: :violation,
       payload: payload,
       observation: error.observation,
       violations: error.violations,
       stacktrace: stacktrace
     }}
  end

  defp test_exception(reason, kind, stacktrace, payload) do
    {:error,
     %Failure{
       kind: :test_exception,
       payload: payload,
       exception: reason,
       raise_kind: kind,
       stacktrace: stacktrace
     }}
  end

  defp exception_failure(kind, reason, stacktrace, payload, config) do
    if Enum.any?(config.oracles, &(&1.name == :no_crash)) do
      {:error,
       %Failure{
         kind: :violation,
         payload: payload,
         observation: nil,
         violations: [Havoc.Oracle.crash_violation(kind, reason, stacktrace)],
         exception: reason,
         raise_kind: kind,
         stacktrace: stacktrace
       }}
    else
      {:error,
       %Failure{
         kind: :test_exception,
         payload: payload,
         exception: reason,
         raise_kind: kind,
         stacktrace: stacktrace
       }}
    end
  end

  @doc "Persists and emits a violation, or reraises a non-security test failure."
  @spec report!(failure :: Failure.t(), config :: map()) :: no_return()
  def report!(%Failure{kind: :test_exception} = failure, _config) do
    :erlang.raise(failure.raise_kind, failure.exception, failure.stacktrace)
  end

  def report!(%Failure{kind: :violation} = failure, config) do
    pairs =
      Enum.map(failure.violations, fn violation ->
        Havoc.Finding.from_violation(violation, failure.payload, failure.observation, config)
      end)

    findings = Enum.map(pairs, &elem(&1, 0))
    seeds = Enum.map(pairs, &elem(&1, 1))

    if config.persist do
      {:ok, _count} = Havoc.Corpus.import(seeds, corpus_opts(config))
    end

    Enum.each(findings, &Core.Telemetry.finding(:havoc, &1))

    raise Havoc.PropertyError,
      property_id: config.property_id,
      payload: failure.payload,
      findings: findings
  end

  defp maybe_limit_generation_size(generator, nil), do: generator

  defp maybe_limit_generation_size(generator, maximum) do
    StreamData.scale(generator, &min(maximum, &1))
  end

  defp stream_data_options(config) do
    seed = Map.get(config, :initial_seed, ExUnit.configuration()[:seed] || 0)

    [
      initial_seed: {0, 0, seed},
      initial_size: Application.get_env(:stream_data, :initial_size, 1),
      max_runs: config.runs,
      max_run_time: config.max_run_time || :infinity,
      max_shrinking_steps: config.max_shrinking_steps
    ]
  end

  defp corpus_opts(%{corpus_path: nil}), do: []
  defp corpus_opts(config), do: [path: config.corpus_path]
end
