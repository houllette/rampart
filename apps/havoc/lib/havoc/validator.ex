defmodule Havoc.Validator do
  @moduledoc """
  Validates one concrete payload against Havoc's conservative oracle engine.

  Unlike a property search, this action performs no generation or shrinking. It
  executes exactly the supplied seed, making the result suitable as a proof or
  refutation step for human and agent consumers. Confirmed inputs are persisted
  through the ordinary Havoc corpus path by default.
  """

  @behaviour Core.Validator

  alias Core.Validation
  alias Core.Validation.{Action, Evidence, Request}
  alias Havoc.Oracle.Report
  alias Havoc.Property.Failure

  @action_id "havoc.security-property-reproduces.v1"

  @impl true
  def actions, do: [action()]

  @doc false
  @spec action() :: Action.t()
  def action do
    %Action{
      id: @action_id,
      tool: :havoc,
      name: :security_property_reproduces,
      description: "execute one concrete payload and evaluate declared security oracles",
      accepts: [:seed, :finding],
      side_effects: :test_execution,
      meta: %{requires: [:target, :oracles], generation: :none}
    }
  end

  @impl true
  def validate(%Request{} = request, opts) do
    target = Keyword.fetch!(opts, :target)

    unless is_function(target, 1) do
      raise ArgumentError, "Havoc validation requires a one-argument :target function"
    end

    replay_seed = replay_seed!(request.subject, request)
    config = property_config(request, Keyword.get(opts, :property_options, []))

    case Havoc.Property.evaluate_with_report(target, replay_seed.value, config) do
      {:ok, observation, %Report{skipped: []} = report} ->
        Validation.refuted(
          request,
          replay_seed,
          %Evidence{
            summary: "the concrete payload satisfied every configured security oracle",
            facts: %{
              oracle_names: report.passed,
              property_id: config.property_id
            },
            raw: observation
          }
        )

      {:ok, observation, %Report{} = report} ->
        Validation.inconclusive(
          request,
          replay_seed,
          %Evidence{
            summary: "one or more security oracles lacked the observations needed for a verdict",
            facts: %{
              passed_oracle_names: report.passed,
              skipped_oracle_names: report.skipped,
              property_id: config.property_id
            },
            raw: observation
          }
        )

      {:error, %Failure{kind: :violation} = failure} ->
        confirm(request, replay_seed, failure, config)

      {:error, %Failure{kind: :test_exception} = failure} ->
        Validation.inconclusive(
          request,
          replay_seed,
          %Evidence{
            summary:
              "the validation target or oracle failed before a security verdict was possible",
            facts: %{
              kind: failure.raise_kind,
              reason: Exception.format_banner(failure.raise_kind, failure.exception)
            },
            raw: failure
          }
        )
    end
  end

  defp confirm(request, _replay_seed, failure, config) do
    pairs =
      Enum.map(failure.violations, fn violation ->
        Havoc.Finding.from_violation(violation, failure.payload, failure.observation, config)
      end)

    findings = Enum.map(pairs, &elem(&1, 0))
    seeds = Enum.map(pairs, &elem(&1, 1))
    [proof_seed | _rest] = seeds

    if config.persist do
      {:ok, _count} = Havoc.Corpus.import(seeds, corpus_options(config))
    end

    Validation.confirmed(
      request,
      findings,
      proof_seed,
      %Evidence{
        summary: "#{length(findings)} security oracle violation(s) reproduced",
        facts: %{
          categories: Enum.map(findings, & &1.category),
          finding_ids: Enum.map(findings, & &1.id),
          oracle_names: Enum.map(failure.violations, & &1.oracle),
          property_id: config.property_id
        },
        raw: failure
      }
    )
  end

  defp property_config(request, opts) when is_list(opts) do
    classes =
      Enum.uniq([
        :validation | subject_classes(request.subject) ++ Keyword.get(opts, :classes, [])
      ])

    locus = Map.merge(subject_locus(request.subject), Keyword.get(opts, :locus, %{}))

    opts
    |> Keyword.put(:classes, classes)
    |> Keyword.put(:locus, locus)
    |> Keyword.put_new(:property_id, "validation:#{request.id}")
    |> Keyword.put_new(:property_name, "validate #{request.id}")
    |> Keyword.put_new(:module, __MODULE__)
    |> Keyword.put_new(:replay, false)
    |> Havoc.Property.config!()
  end

  defp property_config(_request, opts) do
    raise ArgumentError, "Havoc :property_options must be a keyword list, got: #{inspect(opts)}"
  end

  defp subject_classes(%Core.Seed{classes: classes}), do: classes
  defp subject_classes(%Core.Finding{seed: %Core.Seed{classes: classes}}), do: classes
  defp subject_classes(_subject), do: []

  defp subject_locus(%Core.Finding{} = finding) do
    Map.merge(finding.locus || %{}, %{
      origin_finding_id: finding.id,
      origin_source: finding.source
    })
  end

  defp subject_locus(_subject), do: %{}

  defp replay_seed!(%Core.Seed{} = seed, request), do: normalize_seed(seed, request)

  defp replay_seed!(%Core.Finding{seed: %Core.Seed{} = seed}, request) do
    normalize_seed(seed, request)
  end

  defp replay_seed!(%Core.Finding{} = finding, _request) do
    raise ArgumentError,
          "Havoc validation requires a finding with a concrete Core.Seed, got: #{inspect(finding)}"
  end

  defp normalize_seed(seed, request) do
    id =
      seed.id ||
        Core.Finding.dedupe_id(:havoc, [
          "validation_input",
          request.id,
          Havoc.TermCodec.fingerprint(seed.value)
        ])

    %{seed | id: id, classes: Enum.uniq([:validation | seed.classes])}
  end

  defp corpus_options(%{corpus_path: nil}), do: []
  defp corpus_options(config), do: [path: config.corpus_path]
end
