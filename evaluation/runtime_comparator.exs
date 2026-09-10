defmodule RampartEvaluation.RuntimeComparator do
  @moduledoc false

  @targeted_trace_case "iast.targeted-trace-overhead.v1"
  @cross_process_case "iast.cross-process-boundary-feasibility.v3"

  @targeted_trace_metrics [
    "sample_count",
    "baseline_median_us",
    "targeted_median_us",
    "targeted_p95_us",
    "added_median_us",
    "overhead_ratio"
  ]
  @cross_process_metrics [
    "probe_us",
    "model_evidence_bytes",
    "external_state_probe_us",
    "mailbox_pressure_probe_us",
    "mailbox_pressure_receiver_reductions",
    "distributed_handoff_probe_us"
  ]

  @spec run!([String.t()]) :: map()
  def run!(arguments) do
    {options, paths, invalid} =
      OptionParser.parse(arguments,
        strict: [output: :string],
        aliases: [o: :output]
      )

    if length(paths) < 2 or invalid != [] do
      raise ArgumentError,
            "usage: mix rampart.eval.compare REPORT REPORT [REPORT ...] [--output PATH]"
    end

    reports = Enum.map(paths, &read_report!/1)
    Enum.each(reports, &validate_report!/1)
    ensure_distinct_runtimes!(reports)
    signature = ensure_matching_semantics!(reports)

    comparison = %{
      "schema_version" => 1,
      "status" => "compatible",
      "semantic_signature" => %{
        "case_count" => length(signature),
        "cases" => signature
      },
      "profiles" => Enum.map(reports, &profile/1)
    }

    encoded = JSON.encode!(comparison)

    if output = options[:output] do
      output |> Path.dirname() |> File.mkdir_p!()
      File.write!(output, encoded <> "\n")
    end

    IO.puts(encoded)
    comparison
  end

  defp read_report!(path) do
    report = path |> File.read!() |> JSON.decode!()
    %{path: path, report: report}
  end

  defp validate_report!(%{path: path, report: report}) do
    unless is_map(report) and report["schema_version"] == 2 do
      raise "#{path}: expected Rampart evaluation schema version 2"
    end

    unless report["status"] == "passed" do
      raise "#{path}: evaluation did not pass"
    end

    unless get_in(report, ["summary", "false_confirmations"]) == 0 do
      raise "#{path}: evaluation contains false confirmations"
    end

    validate_runtime!(path, report["runtime"])
    validate_cases!(path, report["cases"])
    validate_summary!(path, report["summary"], report["cases"])
  end

  defp validate_runtime!(path, runtime) when is_map(runtime) do
    required = [
      "profile",
      "runtime_id",
      "otp_release",
      "erts_version",
      "elixir_version",
      "architecture"
    ]

    unless Enum.all?(required, &(is_binary(runtime[&1]) and runtime[&1] != "")) and
             is_integer(runtime["schedulers_online"]) do
      raise "#{path}: runtime manifest is incomplete"
    end

    expected_id =
      "otp-#{runtime["otp_release"]}-erts-#{runtime["erts_version"]}-" <>
        "elixir-#{runtime["elixir_version"]}"

    unless runtime["runtime_id"] == expected_id do
      raise "#{path}: runtime identity does not match its version fields"
    end
  end

  defp validate_runtime!(path, _runtime), do: raise("#{path}: runtime manifest is missing")

  defp validate_cases!(path, cases) when is_list(cases) and cases != [] do
    case_ids = Enum.map(cases, & &1["case_id"])

    unless Enum.all?(case_ids, &is_binary/1) and length(case_ids) == length(Enum.uniq(case_ids)) do
      raise "#{path}: evaluation case IDs are missing or duplicated"
    end

    Enum.each(cases, fn evaluation ->
      case_id = evaluation["case_id"]
      checks = evaluation["checks"]

      unless evaluation["status"] == "passed" and is_list(checks) and checks != [] do
        raise "#{path}: #{case_id} did not pass or is missing its checks"
      end

      check_names = Enum.map(checks, & &1["name"])

      unless Enum.all?(checks, fn check ->
               is_binary(check["name"]) and check["passed"] == true
             end) and length(check_names) == length(Enum.uniq(check_names)) do
        raise "#{path}: #{case_id} contains a failed, malformed, or duplicated check"
      end
    end)
  end

  defp validate_cases!(path, _cases), do: raise("#{path}: evaluation cases are missing")

  defp validate_summary!(path, summary, cases) when is_map(summary) do
    checks_total =
      Enum.reduce(cases, 0, fn evaluation, total ->
        total + length(evaluation["checks"])
      end)

    unless summary["case_count"] == length(cases) and
             summary["checks_total"] == checks_total and
             summary["checks_passed"] == checks_total and
             summary["replay_successes"] == length(cases) do
      raise "#{path}: evaluation summary does not match its cases"
    end
  end

  defp validate_summary!(path, _summary, _cases),
    do: raise("#{path}: evaluation summary is missing")

  defp ensure_distinct_runtimes!(reports) do
    runtime_ids = Enum.map(reports, &get_in(&1.report, ["runtime", "runtime_id"]))

    unless length(runtime_ids) == length(Enum.uniq(runtime_ids)) do
      raise "runtime comparison requires distinct OTP/ERTS/Elixir identities"
    end
  end

  defp ensure_matching_semantics!([baseline | rest]) do
    signature = semantic_signature(baseline.report)

    Enum.each(rest, fn candidate ->
      unless semantic_signature(candidate.report) == signature do
        raise "#{candidate.path}: case IDs or check names differ from #{baseline.path}"
      end
    end)

    signature
  end

  defp semantic_signature(report) do
    report["cases"]
    |> Enum.map(fn evaluation ->
      %{
        "case_id" => evaluation["case_id"],
        "checks" => evaluation["checks"] |> Enum.map(& &1["name"]) |> Enum.sort()
      }
    end)
    |> Enum.sort_by(& &1["case_id"])
  end

  defp profile(%{path: path, report: report}) do
    %{
      "path" => path,
      "runtime" => report["runtime"],
      "summary" => report["summary"],
      "observations" => %{
        "targeted_trace" => case_metrics(report, @targeted_trace_case, @targeted_trace_metrics),
        "cross_process" => case_metrics(report, @cross_process_case, @cross_process_metrics)
      }
    }
  end

  defp case_metrics(report, case_id, metric_names) do
    evaluation = Enum.find(report["cases"], &(&1["case_id"] == case_id))
    Map.take(evaluation["efficiency"], metric_names)
  end
end
