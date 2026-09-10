defmodule Core.ValidationBindingWireTest do
  use ExUnit.Case, async: true

  alias Core.Validation
  alias Core.Validation.{Action, Binding, Evidence, Wire}

  defmodule Validator do
    @behaviour Core.Validator

    @impl true
    def actions do
      [
        %Action{
          id: "test.bound-replay.v1",
          tool: :test_tool,
          name: :bound_replay,
          description: "replay through host-owned validation authority",
          accepts: [:finding],
          side_effects: :test_execution,
          meta: %{requires: [:target], transport_hint: {:host, :bound}}
        }
      ]
    end

    @impl true
    def validate(request, opts) do
      seed = %Core.Seed{
        id: "proof-seed",
        value: Keyword.fetch!(opts, :payload),
        classes: [:counterexample],
        provenance: :counterexample,
        meta: %{bound_authority: Keyword.fetch!(opts, :authority)}
      }

      finding = %Core.Finding{
        id: "proof-finding",
        source: :test_tool,
        category: :test_violation,
        locus: %{module: __MODULE__, input: <<255, 0>>},
        confidence: :high,
        evidence: "the bound target reproduced the violation",
        raw: fn -> :never_serialize end,
        seed: seed,
        observed_at: ~U[2026-01-01 00:00:00Z]
      }

      Validation.confirmed(
        request,
        [finding],
        seed,
        %Evidence{
          summary: "bound validation reproduced",
          facts: %{attempts: 1, sink: {:erlang, :binary_to_term, 1}},
          artifacts: [
            %{
              id: "trace-1",
              sha256: String.duplicate("a", 64),
              size_bytes: 128,
              content_schema: "rampart.trace.v1"
            }
          ],
          raw: self()
        },
        %{correlation: :test_run}
      )
    end
  end

  test "binding resolves inert references under host-owned authority" do
    candidate = candidate()

    binding =
      Binding.new!(Validator, "test.bound-replay.v1",
        resolver: fn :finding, "candidate-1" -> {:ok, candidate} end,
        validator_options: [payload: <<255, 0>>, authority: :current_session],
        request_context: %{tenant: "tenant-1"}
      )

    assert {:ok, result} =
             Binding.invoke(binding, %{
               "subject_type" => "finding",
               "subject_id" => "candidate-1"
             })

    assert result.verdict == :confirmed
    assert result.seed.value == <<255, 0>>
    assert result.seed.meta.bound_authority == :current_session
  end

  test "binding rejects caller attempts to smuggle executable options" do
    binding = bound_validation()

    assert {:error, {:unknown_subject_reference_fields, ["scope"]}} =
             Binding.invoke(binding, %{
               "subject_type" => "finding",
               "subject_id" => "candidate-1",
               "scope" => "allow-all"
             })
  end

  test "binding rejects resolver identity substitution" do
    binding =
      Binding.new!(Validator, "test.bound-replay.v1",
        resolver: fn :finding, "candidate-1" -> {:ok, %{candidate() | id: "other"}} end,
        validator_options: [payload: "payload", authority: :current_session]
      )

    assert {:error, {:resolved_subject_mismatch, :finding, "candidate-1", _subject}} =
             Binding.invoke(binding, %{subject_type: :finding, subject_id: "candidate-1"})
  end

  test "wire projection is bounded, JSON-safe, and integrity checked" do
    {:ok, result} =
      bound_validation()
      |> Binding.invoke(%{subject_type: :finding, subject_id: "candidate-1"})

    projection = Wire.result(result)
    encoded = Wire.encode!(projection)

    assert projection["schema_version"] == 1
    assert projection["verdict"] == "confirmed"
    assert projection["seed"]["value_included"] == false
    refute Map.has_key?(projection["seed"], "value")
    refute encoded =~ "never_serialize"
    assert :ok = Wire.verify(projection)

    tampered = put_in(projection, ["evidence", "summary"], "different")
    assert {:error, :digest_mismatch} = Wire.verify(tampered)

    model_text = Wire.model_text(result)
    assert model_text =~ "Action ID: test.bound-replay.v1"
    assert model_text =~ "Verdict: confirmed"
    assert model_text =~ "Evidence summary: bound validation reproduced"
    assert model_text =~ "Finding count: 1"
    assert model_text =~ "Replay seed ID: proof-seed"
  end

  test "wire projection fingerprints malformed binary values when explicitly included" do
    {:ok, result} =
      bound_validation()
      |> Binding.invoke(%{subject_type: :finding, subject_id: "candidate-1"})

    projection = Wire.result(result, include_seed_value: true)

    assert %{
             "$rampart" => "binary_omitted",
             "sha256" => sha256,
             "size_bytes" => 2
           } = projection["seed"]["value"]

    assert byte_size(sha256) == 64
    assert is_binary(Wire.encode!(projection))
  end

  test "wire action schema only accepts an opaque subject reference" do
    [action] = Validation.actions(Validator)
    descriptor = Wire.action(action)
    schema = Wire.input_schema(action)

    assert descriptor["id"] == action.id
    assert descriptor["side_effects"] == "test_execution"
    assert :ok = Wire.verify(descriptor)
    assert schema["additionalProperties"] == false
    assert schema["required"] == ["subject_type", "subject_id"]
    assert schema["properties"]["subject_type"]["enum"] == ["finding"]
    assert is_binary(JSON.encode!(schema))
  end

  defp bound_validation do
    candidate = candidate()

    Binding.new!(Validator, "test.bound-replay.v1",
      resolver: fn :finding, "candidate-1" -> {:ok, candidate} end,
      validator_options: [payload: <<255, 0>>, authority: :current_session]
    )
  end

  defp candidate do
    %Core.Finding{
      id: "candidate-1",
      source: :test_tool,
      category: :candidate,
      locus: %{module: __MODULE__},
      confidence: :medium,
      evidence: "candidate observation",
      observed_at: ~U[2026-01-01 00:00:00Z]
    }
  end
end
