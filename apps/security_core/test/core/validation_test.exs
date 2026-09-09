defmodule Core.ValidationTest do
  use ExUnit.Case, async: true

  alias Core.Validation
  alias Core.Validation.{Action, Evidence, Result}

  defmodule Validator do
    @behaviour Core.Validator

    @impl true
    def actions do
      [
        %Action{
          id: "test.reproduce.v1",
          tool: :test_tool,
          name: :reproduce,
          description: "reproduce a concrete test finding",
          accepts: [:finding, :hypothesis],
          side_effects: :none
        }
      ]
    end

    @impl true
    def validate(request, opts) do
      seed = %Core.Seed{id: "replay-seed", value: opts[:value], provenance: :counterexample}

      finding = %Core.Finding{
        id: "confirmed-finding",
        source: :test_tool,
        category: :test_violation,
        locus: %{module: __MODULE__},
        confidence: :high,
        evidence: "the invariant failed again",
        seed: seed,
        observed_at: DateTime.utc_now()
      }

      Validation.confirmed(
        request,
        [finding],
        seed,
        %Evidence{summary: "reproduced", facts: %{attempts: 1}}
      )
    end
  end

  defmodule BrokenValidator do
    @behaviour Core.Validator

    @impl true
    def actions, do: Validator.actions()

    @impl true
    def validate(request, _opts) do
      %Result{
        id: request.id,
        request_id: request.id,
        action: request.action,
        tool: request.action.tool,
        verdict: :confirmed,
        evidence: %Evidence{summary: "claimed confirmation"},
        findings: [],
        seed: %Core.Seed{id: "replay", value: "x"},
        observed_at: DateTime.utc_now()
      }
    end
  end

  test "discovers versioned actions and derives stable request IDs" do
    [action] = Validation.actions(Validator)
    finding = finding()

    first = Validation.request(action, finding)
    second = Validation.request(action, finding)

    assert action.id == "test.reproduce.v1"
    assert action.side_effects == :none
    assert first.id == second.id
    assert first.subject == finding
  end

  test "dispatches validation, emits a span, and emits confirmed findings" do
    events = [
      [:core, :test_tool, :validation, :start],
      [:core, :test_tool, :validation, :stop],
      [:core, :test_tool, :finding]
    ]

    handler_id = {__MODULE__, self()}
    :ok = :telemetry.attach_many(handler_id, events, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler_id) end)

    [action] = Validation.actions(Validator)
    request = Validation.request(action, finding())

    assert %Result{verdict: :confirmed, findings: [confirmed], seed: seed} =
             Validation.run(Validator, request, value: "payload")

    assert confirmed.id == "confirmed-finding"
    assert seed.value == "payload"
    assert :validation in seed.classes

    assert_receive {:telemetry, [:core, :test_tool, :validation, :start], _, start_metadata}
    assert start_metadata.action == action.id

    assert_receive {:telemetry, [:core, :test_tool, :finding], %{}, %{finding: ^confirmed}}

    assert_receive {:telemetry, [:core, :test_tool, :validation, :stop], _, stop_metadata}
    assert stop_metadata.verdict == :confirmed
    assert stop_metadata.finding_count == 1
  end

  test "rejects a claimed confirmation without proof findings" do
    [action] = Validation.actions(BrokenValidator)
    request = Validation.request(action, finding())

    assert_raise ArgumentError, ~r/violates the Core.Validation contract/, fn ->
      Validation.run(BrokenValidator, request)
    end
  end

  test "accepts structured IAST hypotheses without prescribing a web locus" do
    [action] = Validation.actions(Validator)

    hypothesis = %Core.Hypothesis{
      id: "taint-claim-1",
      source: :iast,
      kind: :taint_reaches_sink,
      claim: "message payload reaches binary_to_term/1",
      locus: %{context: :otp, module: Example.Server, sink: {:erlang, :binary_to_term, 1}}
    }

    request = Validation.request(action, hypothesis)

    assert request.subject == hypothesis
    assert is_binary(request.id)
  end

  test "requires IDs for replayable validation subjects" do
    [action] = Validation.actions(Validator)

    assert_raise ArgumentError, ~r/require a non-empty ID/, fn ->
      Validation.request(action, %Core.Finding{source: :test_tool})
    end
  end

  test "rejects unversioned action identifiers" do
    action = %Action{
      id: "test.reproduce",
      tool: :test_tool,
      name: :reproduce,
      description: "missing semantic version",
      accepts: [:finding],
      side_effects: :none
    }

    assert_raise ArgumentError, ~r/invalid validation action/, fn ->
      Validation.request(action, finding())
    end
  end

  defp finding do
    %Core.Finding{
      id: "candidate-finding",
      source: :test_tool,
      category: :candidate,
      confidence: :medium,
      evidence: "candidate observation",
      observed_at: DateTime.utc_now()
    }
  end

  @doc false
  def handle_event(event, measurements, metadata, parent) do
    send(parent, {:telemetry, event, measurements, metadata})
  end
end
