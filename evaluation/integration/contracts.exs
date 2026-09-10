Code.require_file("assertions.exs", __DIR__)
Code.require_file("../../examples/bound_validation.exs", __DIR__)

defmodule Integration.Contracts do
  import ExUnit.Assertions
  alias Core.Validation.{Binding, Wire}
  alias RampartExample.BoundValidation, as: Host

  def run do
    File.mkdir_p!("proofs")
    {:ok, supervisor} = Task.Supervisor.start_link()
    seed = %Core.Seed{id: "contract-input", value: <<255, 0>>, provenance: :generated}
    options = [output_limit: 4096, artifact_directory: "proofs/artifacts"]

    verdicts =
      for {status, verdict} <- [{500, "confirmed"}, {200, "refuted"}, {nil, "inconclusive"}] do
        binding = havoc(seed, fn _ -> %{status: status, raw: fn -> :private end} end)
        assert {:ok, result} = call(supervisor, binding, Wire.subject_reference(seed), options)
        assert result["verdict"] == verdict
        assert :ok = Wire.verify(result)
        refute Wire.encode!(result) =~ "private"
        refute Map.has_key?(result["seed"], "value")
        verdict
      end

    assert [saved] = Havoc.Corpus.load(path: "proofs/contract-corpus.json")
    assert saved.value == seed.value

    File.write!(
      "proofs/subject-reference.json",
      saved |> Wire.subject_reference() |> Wire.encode!()
    )

    reference = "proofs/subject-reference.json" |> File.read!() |> JSON.decode!()

    assert {:ok, replay} =
             call(supervisor, havoc(saved, fn _ -> %{status: 500} end), reference, options)

    assert replay["verdict"] == "confirmed"

    denied =
      Binding.new!(Havoc.Validator, "havoc.security-property-reproduces.v1",
        resolver: fn _, _ -> {:error, :not_in_current_host_scope} end
      )

    assert {:error, {:subject_unavailable, :not_in_current_host_scope}} =
             call(supervisor, denied, reference, options)

    binding = havoc(seed, fn _ -> %{status: 200} end)

    for forbidden <- ["scope", "target", "resolver", "artifact_directory", "output_limit"] do
      assert {:error, {:unknown_subject_reference_fields, [^forbidden]}} =
               call(
                 supervisor,
                 binding,
                 Map.put(Wire.subject_reference(seed), forbidden, "transcript"),
                 options
               )
    end

    for malformed <- [
          %{},
          %{"subject_type" => "seed", "subject_id" => ""},
          %{"subject_type" => "module", "subject_id" => seed.id}
        ] do
      assert {:error, _} = call(supervisor, binding, malformed, options)
    end

    invalid =
      Binding.new!(Havoc.Validator, "havoc.security-property-reproduces.v1",
        resolver: fn _, _ -> {:ok, seed} end,
        validator_options: [target: :invalid]
      )

    assert {:error, {:validator_crash, _}} =
             call(supervisor, invalid, Wire.subject_reference(seed), options)

    parent = self()

    slow =
      havoc(seed, fn _ ->
        send(parent, {:executing, self()})
        Process.sleep(:infinity)
      end)

    task = Host.start(supervisor, slow, Wire.subject_reference(seed), options)
    assert_receive {:executing, worker}
    assert {:error, :cancelled} = Host.cancel(task)
    refute Process.alive?(worker)
    task = Host.start(supervisor, slow, Wire.subject_reference(seed), options)
    assert_receive {:executing, worker}
    assert {:error, :deadline_exceeded} = Host.await(task, 10)
    refute Process.alive?(worker)

    # Completed target failure is domain evidence; a crashed validator above is a tool failure.
    broken = havoc(seed, fn _ -> raise "fixture unavailable" end)

    assert {:ok, %{"verdict" => "inconclusive"}} =
             call(supervisor, broken, Wire.subject_reference(seed), options)

    huge = havoc(seed, fn _ -> raise String.duplicate("oversized evidence ", 10_000) end)
    assert {:ok, summary} = call(supervisor, huge, Wire.subject_reference(seed), options)
    assert summary["verdict"] == "inconclusive"
    assert summary["full_result_externalized"]
    assert byte_size(Wire.encode!(summary)) <= options[:output_limit]
    artifact = File.read!("proofs/artifacts/" <> summary["artifact"]["sha256"] <> ".json")
    assert byte_size(artifact) == summary["artifact"]["size_bytes"]

    assert Base.encode16(:crypto.hash(:sha256, artifact), case: :lower) ==
             summary["artifact"]["sha256"]

    assert :ok = artifact |> JSON.decode!() |> Wire.verify()

    scope_failure(supervisor, options)
    static_replay(supervisor, options)
    Supervisor.stop(supervisor)

    Integration.Assertions.finish(%{
      verdicts: verdicts,
      checks: [
        "persisted_replay",
        "new_host_authority",
        "malformed_references",
        "option_smuggling",
        "scope_denial",
        "validator_crash",
        "deadline",
        "cancellation",
        "target_failure",
        "bounded_artifact_output",
        "syntactic_replay"
      ]
    })
  end

  defp havoc(seed, target) do
    Binding.new!(Havoc.Validator, "havoc.security-property-reproduces.v1",
      resolver: fn :seed, id -> if id == seed.id, do: {:ok, seed}, else: {:error, :missing} end,
      validator_options: [
        target: target,
        property_options: [
          oracles: [:no_500],
          corpus_path: "proofs/contract-corpus.json",
          property_id: "external-contract"
        ]
      ]
    )
  end

  defp call(supervisor, binding, reference, options),
    do: supervisor |> Host.start(binding, reference, options) |> Host.await(5000)

  defp scope_failure(supervisor, options) do
    scan =
      Foray.target("http://127.0.0.1", scope: Core.Scope.DenyAll)
      |> Foray.fuzz_path(wordlist: "unused")

    finding = %Core.Finding{
      id: "candidate",
      source: :foray,
      category: :exposed_path,
      locus: %{
        identity_version: 3,
        job_id: scan.id <> ":1",
        inputs: %{"FUZZ" => "admin"},
        url: "http://127.0.0.1/admin",
        method: "GET"
      },
      confidence: :medium,
      evidence: "candidate",
      observed_at: DateTime.utc_now(),
      seed: %Core.Seed{id: "admin", value: "admin", provenance: :wordlist}
    }

    binding =
      Binding.new!(Foray.Validator, "foray.http-match-reproduces.v1",
        resolver: fn _, _ -> {:ok, finding} end,
        validator_options: [scan: scan]
      )

    assert {:error, {:scope_denied, _}} =
             call(supervisor, binding, Wire.subject_reference(finding), options)
  end

  defp static_replay(supervisor, options) do
    rules = [RampartSAST.Rules.UnsafeAtom]
    source = "defmodule ContractTarget do\n def run(value), do: String.to_atom(value)\nend\n"
    assert %{findings: [finding]} = RampartSAST.scan_sources([{"target.ex", source}], rules)

    for {current, verdict} <- [
          {source, "confirmed"},
          {String.replace(source, "to_atom", "to_existing_atom"), "refuted"},
          {"defmodule Broken do", "inconclusive"}
        ] do
      binding =
        Binding.new!(RampartSAST.Validator, "sast.rule-matches-source.v1",
          resolver: fn _, _ -> {:ok, finding} end,
          validator_options: [rules: rules, source: current]
        )

      assert {:ok, result} = call(supervisor, binding, Wire.subject_reference(finding), options)
      assert result["verdict"] == verdict
    end
  end
end

Integration.Contracts.run()
