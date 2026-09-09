defmodule Foray.Validator do
  @moduledoc """
  Replays one concrete ffuf match against its original scan plan.

  The validator replaces every wordlist with the exact recorded input, disables
  recursion, and preserves the plan's scope, rate, engine, and request
  configuration. It confirms only when the same stable finding identity is
  observed again.
  """

  @behaviour Core.Validator

  alias Core.Validation
  alias Core.Validation.{Action, Evidence, Request}
  alias Foray.{Audit, JobBuilder, PipelineError, Runtime, Scan, Target, Wordlist}

  @action_id "foray.http-match-reproduces.v1"

  @impl true
  def actions, do: [action()]

  @doc false
  @spec action() :: Action.t()
  def action do
    %Action{
      id: @action_id,
      tool: :foray,
      name: :http_match_reproduces,
      description: "replay a concrete ffuf input and require the same HTTP match",
      accepts: [:finding],
      side_effects: :authorized_probe,
      meta: %{requires_scope: true, requires: [:scan_plan]}
    }
  end

  @impl true
  def validate(%Request{subject: %Core.Finding{} = candidate} = request, opts) do
    scan = Keyword.fetch!(opts, :scan)

    unless match?(%Scan{}, scan) do
      raise ArgumentError, "Foray validation requires the originating Foray.Scan in :scan"
    end

    inputs = inputs!(candidate, scan.wordlists)
    seed = replay_seed(candidate, scan, inputs)
    validation_scan = exact_scan(scan, inputs, candidate)

    try do
      case reproduce(validation_scan, candidate, inputs) do
        {:confirmed, finding} ->
          finding = %{
            finding
            | seed: seed,
              raw: %{observation: finding.raw, validated_from: candidate.id}
          }

          Validation.confirmed(
            request,
            [finding],
            seed,
            %Evidence{
              summary: "the recorded HTTP match reproduced with the same concrete input",
              facts: %{
                finding_id: finding.id,
                method: finding.locus[:method],
                status: finding.locus[:status],
                url: finding.locus[:url]
              },
              raw: finding.raw
            }
          )

        :refuted ->
          Validation.refuted(
            request,
            seed,
            %Evidence{
              summary: "the recorded HTTP match did not reproduce",
              facts: %{finding_id: candidate.id, url: candidate.locus[:url], inputs: inputs}
            }
          )

        {:inconclusive, reason} ->
          Validation.inconclusive(
            request,
            seed,
            %Evidence{
              summary:
                "Foray could not identify the originating job without broadening the probe",
              facts: %{reason: reason, finding_id: candidate.id, url: candidate.locus[:url]}
            }
          )
      end
    rescue
      exception in [PipelineError, Core.Runner.Error, Core.Runner.TimeoutError] ->
        Validation.inconclusive(
          request,
          seed,
          %Evidence{
            summary: "Foray could not complete the HTTP validation probe",
            facts: %{reason: Exception.message(exception)},
            raw: exception
          }
        )
    end
  end

  defp reproduce(scan, candidate, inputs) do
    jobs = scan |> JobBuilder.build() |> matching_jobs(candidate, inputs)

    if jobs == [] do
      {:inconclusive, :originating_job_not_found}
    else
      Core.Scope.ensure_all_authorized!(Enum.map(jobs, & &1.target), scan.scope)
      Runtime.validate!(scan)
      run_jobs(jobs, scan, candidate.id)
    end
  end

  defp run_jobs(jobs, scan, candidate_id) do
    Enum.reduce_while(jobs, :refuted, fn job, _result ->
      Core.Scope.ensure_authorized!(job.target, scan.scope)

      metadata = %{
        job_id: job.id,
        target: job.target.url,
        engine: scan.engine.module,
        validation: true
      }

      Audit.emit(scan.audit, :job_launch, metadata)
      Core.Telemetry.launch(:foray, job.target.url)

      case find_candidate(job, scan, candidate_id) do
        nil -> {:cont, :refuted}
        finding -> {:halt, {:confirmed, finding}}
      end
    end)
  end

  defp matching_jobs(jobs, %Core.Finding{locus: locus}, inputs) when is_map(locus) do
    case locus[:url] do
      url when is_binary(url) ->
        Enum.filter(jobs, &target_can_render?(&1.target.url, url, inputs))

      _other ->
        []
    end
  end

  defp target_can_render?(template, observed_url, inputs) do
    candidates = [
      render_url(template, inputs, &Function.identity/1),
      render_url(template, inputs, &URI.encode/1),
      render_url(template, inputs, &URI.encode_www_form/1)
    ]

    Enum.any?(candidates, &same_url?(&1, observed_url))
  end

  defp render_url(template, inputs, encoder) do
    Enum.reduce(inputs, template, fn {keyword, value}, url ->
      String.replace(url, keyword, encoder.(value))
    end)
  end

  defp same_url?(left, right) do
    case {Target.parse(left), Target.parse(right)} do
      {{:ok, left}, {:ok, right}} -> left.url == right.url
      _other -> left == right
    end
  end

  defp find_candidate(job, scan, candidate_id) do
    job
    |> scan.engine.module.stream(scan.engine.opts)
    |> Enum.find(fn
      %Core.Finding{} = finding ->
        authorize_observation!(finding, scan.scope)
        finding.id == candidate_id

      other ->
        raise PipelineError, stage: :engine, reason: {:invalid_finding, other}
    end)
  end

  defp authorize_observation!(%Core.Finding{locus: %{url: url}}, scope) when is_binary(url) do
    case Target.parse(url) do
      {:ok, target} ->
        Core.Scope.ensure_authorized!(target, scope)

      {:error, reason} ->
        raise PipelineError, stage: :engine, reason: {:invalid_result_url, reason}
    end
  end

  defp authorize_observation!(_finding, _scope) do
    raise PipelineError, stage: :engine, reason: :finding_missing_url
  end

  defp exact_scan(scan, inputs, candidate) do
    wordlists =
      Enum.map(scan.wordlists, fn %Wordlist{} = wordlist ->
        value = Map.fetch!(inputs, wordlist.keyword)

        input_seed = %Core.Seed{
          id:
            Core.Finding.dedupe_id(:foray, [
              "validation_input",
              candidate.id,
              wordlist.keyword,
              value
            ]),
          value: value,
          classes: Enum.uniq([:validation | wordlist.classes]),
          provenance: :promoted_finding,
          origin: {:foray, candidate.id},
          meta: %{action: @action_id}
        }

        %{wordlist | source: {:seeds, [input_seed]}}
      end)

    %{
      scan
      | wordlists: wordlists,
        recursion: nil,
        max_concurrency: 1,
        metadata: Map.put(scan.metadata, :validation, true)
    }
  end

  defp inputs!(%Core.Finding{source: :foray, id: id} = candidate, wordlists)
       when is_binary(id) and id != "" do
    inputs = decoded_raw_inputs(candidate) || locus_inputs(candidate, wordlists)
    required = Enum.map(wordlists, & &1.keyword)

    if is_map(inputs) and required != [] and Enum.all?(required, &is_binary(inputs[&1])) do
      Map.take(inputs, required)
    else
      raise ArgumentError,
            "Foray validation requires one concrete recorded value for every fuzz keyword"
    end
  end

  defp inputs!(candidate, _wordlists) do
    raise ArgumentError, "not a valid Foray finding: #{inspect(candidate)}"
  end

  defp decoded_raw_inputs(%Core.Finding{raw: %{"input" => encoded}}) when is_map(encoded) do
    Enum.reduce_while(encoded, %{}, fn
      {keyword, value}, inputs when is_binary(keyword) and is_binary(value) ->
        case Base.decode64(value) do
          {:ok, decoded} -> {:cont, Map.put(inputs, keyword, decoded)}
          :error -> {:halt, nil}
        end

      _entry, _inputs ->
        {:halt, nil}
    end)
  end

  defp decoded_raw_inputs(_candidate), do: nil

  defp locus_inputs(%Core.Finding{locus: locus, seed: %Core.Seed{value: value}}, [wordlist])
       when is_map(locus) and is_binary(value) do
    keyword = locus[:keyword] || wordlist.keyword
    %{keyword => value}
  end

  defp locus_inputs(%Core.Finding{locus: locus}, _wordlists) when is_map(locus) do
    case {locus[:keyword], locus[:input]} do
      {keyword, value} when is_binary(keyword) and is_binary(value) -> %{keyword => value}
      _other -> nil
    end
  end

  defp locus_inputs(_candidate, _wordlists), do: nil

  defp replay_seed(candidate, scan, inputs) do
    classes =
      case candidate.seed do
        %Core.Seed{classes: classes} -> classes
        _other -> []
      end

    %Core.Seed{
      id: Core.Finding.dedupe_id(:foray, ["http_validation", candidate.id, scan.id]),
      value: %{finding_id: candidate.id, inputs: inputs, scan_id: scan.id},
      classes: Enum.uniq([:validation, :http | classes]),
      provenance: :promoted_finding,
      origin: {:foray, candidate.id},
      meta: %{
        action: @action_id,
        method: candidate.locus[:method],
        url: candidate.locus[:url]
      }
    }
  end
end
