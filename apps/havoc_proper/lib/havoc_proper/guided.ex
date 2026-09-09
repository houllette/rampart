defmodule HavocProper.Guided do
  @moduledoc """
  Runs PropEr targeted PBT with per-candidate OTP line coverage as fitness.

  Corpus regressions still run first through Havoc. PropEr then owns targeted
  generation/search; Havoc's existing evaluator owns oracles, normalized
  findings, and durable concrete counterexamples. PropEr targeted properties do
  not provide ordinary shrinking guarantees, so a discovered candidate is
  persisted exactly as observed.
  """

  alias HavocProper.{Archive, Coverage, Sample}

  @guided_schema [
    coverage_modules: [type: {:list, :atom}, required: true],
    search_steps: [type: :pos_integer, default: 1_000],
    search_strategy: [
      type: {:in, [:simulated_annealing, :hill_climbing]},
      default: :simulated_annealing
    ],
    fitness_bonus: [type: {:or, [{:fun, 1}, nil]}, default: nil],
    persist_coverage: [type: :boolean, default: true],
    max_coverage_seeds: [type: :non_neg_integer, default: 32]
  ]

  @guided_keys Keyword.keys(@guided_schema)

  @doc "Runs one coverage-guided security property and raises on a violation."
  @spec check!(PropCheck.type(), keyword(), (term() -> term())) :: :ok
  def check!(generator, opts, target) when is_function(target, 1) do
    {guided_opts, property_opts} = Keyword.split(opts, @guided_keys)
    guided = guided_opts |> NimbleOptions.validate!(@guided_schema) |> Map.new()
    config = Havoc.Property.config!(property_opts)
    telemetry = Map.put(Havoc.Property.metadata(config), :backend, :proper_targeted)

    Core.Telemetry.span(:havoc, :property, telemetry, fn ->
      replayed = Havoc.Property.replay!(target, config)

      if config.corpus_only do
        {:ok,
         Map.merge(telemetry, %{
           outcome: :ok,
           finding_count: 0,
           replayed: replayed,
           search_steps: 0
         })}
      else
        run_search!(generator, target, config, guided, replayed, telemetry)
      end
    end)
  end

  defp run_search!(generator, target, config, guided, replayed, telemetry) do
    {:ok, archive} = Archive.start_link(guided.max_coverage_seeds)

    try do
      result =
        Coverage.with_modules(guided.coverage_modules, fn ->
          run_proper(property(generator, target, config, guided, archive), guided)
        end)

      reraise_archive_error!(Archive.error(archive))
      seeds = Archive.seeds(archive, config)

      case search_result(result, target, config) do
        :ok ->
          persist_coverage!(seeds, config, guided)

          {:ok,
           Map.merge(telemetry, %{
             outcome: :ok,
             finding_count: 0,
             replayed: replayed,
             search_steps: guided.search_steps,
             coverage_seed_count: length(seeds)
           })}

        {:error, %Havoc.Property.Failure{kind: :violation} = failure} ->
          persist_coverage!(seeds, config, guided)
          Havoc.Property.report!(failure, config)

        {:error, failure} ->
          Havoc.Property.report!(failure, config)
      end
    after
      Agent.stop(archive)
    end
  end

  @spec property(PropCheck.type(), (term() -> term()), map(), map(), Agent.agent()) ::
          :proper.outer_test()
  defp property(generator, target, config, guided, archive) do
    generator
    |> :proper.exists(
      fn payload ->
        {evaluation, covered_lines} =
          Coverage.measure(guided.coverage_modules, fn ->
            Havoc.Property.evaluate(target, payload, config)
          end)

        coverage_fitness = length(covered_lines)

        preliminary = %Sample{
          payload: payload,
          evaluation: evaluation,
          covered_lines: covered_lines,
          coverage_fitness: coverage_fitness,
          fitness: coverage_fitness
        }

        case calculate_fitness(guided.fitness_bonus, preliminary) do
          {:ok, fitness} ->
            sample = %{preliminary | fitness: fitness}
            :ok = Archive.observe(archive, payload, covered_lines, fitness)
            true = :proper_target.update_uv(sample.fitness, :inf)
            match?({:error, _failure}, evaluation)

          {:error, kind, reason, stacktrace} ->
            :ok = Archive.record_error(archive, kind, reason, stacktrace)
            true
        end
      end,
      true
    )
    |> :proper.test_to_outer_test()
  end

  defp calculate_fitness(fun, sample) do
    {:ok, sample.coverage_fitness + fitness_bonus(fun, sample)}
  rescue
    error -> {:error, :error, error, __STACKTRACE__}
  catch
    kind, reason -> {:error, kind, reason, __STACKTRACE__}
  end

  defp fitness_bonus(nil, _sample), do: 0

  defp fitness_bonus(fun, sample) do
    case fun.(sample) do
      value when is_number(value) -> value
      other -> raise ArgumentError, "fitness_bonus must return a number, got: #{inspect(other)}"
    end
  end

  defp reraise_archive_error!(nil), do: :ok

  defp reraise_archive_error!({kind, reason, stacktrace}) do
    :erlang.raise(kind, reason, stacktrace)
  end

  @spec run_proper(:proper.outer_test(), map()) :: PropCheck.long_result()
  defp run_proper(property, guided) do
    PropCheck.counterexample(property, proper_options(guided))
  after
    :proper.clean_garbage()
  end

  defp proper_options(guided) do
    [
      :quiet,
      {:search_steps, guided.search_steps},
      {:search_strategy, guided.search_strategy}
    ]
  end

  defp persist_coverage!([], _config, _guided), do: :ok
  defp persist_coverage!(_seeds, _config, %{persist_coverage: false}), do: :ok
  defp persist_coverage!(_seeds, %{persist: false}, _guided), do: :ok

  defp persist_coverage!(seeds, config, _guided) do
    {:ok, _count} = Havoc.Corpus.import(seeds, corpus_opts(config))
    :ok
  end

  defp search_result(true, _target, _config), do: :ok

  defp search_result([payload], target, config) do
    case Havoc.Property.evaluate(target, payload, config) do
      {:error, failure} ->
        {:error, failure}

      {:ok, _observation} ->
        raise "PropEr returned a counterexample that no longer violates the property"
    end
  end

  defp search_result({:error, reason}, _target, _config) do
    raise "PropEr targeted search failed: #{inspect(reason)}"
  end

  defp search_result(other, _target, _config) do
    raise "unexpected PropEr targeted-search result: #{inspect(other)}"
  end

  defp corpus_opts(%{corpus_path: nil}), do: []
  defp corpus_opts(config), do: [path: config.corpus_path]
end
