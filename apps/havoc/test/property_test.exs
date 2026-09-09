defmodule Havoc.PropertyTest do
  use ExUnit.Case, async: true

  alias Core.Seed
  alias Havoc.{Property, PropertyError}

  setup context do
    path =
      Path.join(
        System.tmp_dir!(),
        "havoc-property-#{context.test}-#{System.unique_integer([:positive])}.json"
      )

    on_exit(fn -> File.rm_rf(path) end)
    %{path: path}
  end

  test "persists StreamData's shrunk concrete counterexample and emits normalized findings", %{
    path: path
  } do
    event = [:core, :havoc, :finding]
    handler_id = {__MODULE__, self(), make_ref()}
    :ok = :telemetry.attach(handler_id, event, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler_id) end)

    error =
      assert_raise PropertyError, fn ->
        Property.check!(
          StreamData.integer(10..20),
          [
            property_id: "Example:never-500",
            property_name: "never returns 500",
            module: __MODULE__,
            oracles: [:no_500],
            corpus_path: path,
            initial_seed: 42,
            runs: 20
          ],
          fn _payload -> %{status: 500} end
        )
      end

    assert error.payload == 10
    assert [%Core.Finding{source: :havoc, category: :crash} = finding] = error.findings
    assert finding.seed.value == 10
    assert finding.seed.provenance == :counterexample
    assert finding.seed.origin == {:havoc, finding.id}

    assert [%Seed{value: 10, meta: %{property_id: "Example:never-500"}}] =
             Havoc.Corpus.load(path: path)

    assert_receive {:telemetry, ^event, %{}, %{finding: ^finding}}
  end

  test "replays persisted counterexamples before random generation", %{path: path} do
    seed = %Seed{
      id: "persisted",
      value: "known",
      classes: [:no_500],
      provenance: :counterexample,
      origin: {:havoc, "old-finding"},
      meta: %{property_id: "Example:replay", oracle: :no_500}
    }

    :ok = Havoc.Corpus.put(seed, path: path)

    assert_raise PropertyError, fn ->
      Property.check!(
        StreamData.constant("random"),
        [
          property_id: "Example:replay",
          property_name: "replay",
          module: __MODULE__,
          oracles: [:no_500],
          corpus_path: path,
          persist: false
        ],
        fn payload ->
          send(self(), {:evaluated, payload})
          %{status: if(payload == "known", do: 500, else: 200)}
        end
      )
    end

    assert_received {:evaluated, "known"}
    refute_received {:evaluated, "random"}
  end

  test "corpus-only mode never evaluates the random generator", %{path: path} do
    assert :ok =
             Property.check!(
               StreamData.constant("random"),
               [
                 property_id: "Example:empty-replay",
                 property_name: "empty replay",
                 module: __MODULE__,
                 oracles: [:no_500],
                 corpus_path: path,
                 corpus_only: true
               ],
               fn payload ->
                 flunk("random generator ran in corpus-only mode: #{inspect(payload)}")
               end
             )
  end

  test "no_crash turns target exceptions into durable violations", %{path: path} do
    error =
      assert_raise PropertyError, fn ->
        Property.check!(
          StreamData.constant("bad"),
          [
            property_id: "Example:no-crash",
            property_name: "does not crash",
            module: __MODULE__,
            oracles: [:no_crash],
            corpus_path: path
          ],
          fn _payload -> raise ArgumentError, "unsafe parser" end
        )
      end

    assert [%Core.Finding{category: :crash, evidence: evidence}] = error.findings
    assert evidence =~ "ArgumentError"
    assert [%Seed{value: "bad"}] = Havoc.Corpus.load(path: path)
  end

  test "ordinary test exceptions are reraised and never mislabeled as findings", %{path: path} do
    assert_raise RuntimeError, "broken test setup", fn ->
      Property.check!(
        StreamData.constant("bad"),
        [
          property_id: "Example:setup-error",
          property_name: "setup error",
          module: __MODULE__,
          oracles: [:no_500],
          corpus_path: path
        ],
        fn _payload -> raise "broken test setup" end
      )
    end

    assert Havoc.Corpus.load(path: path) == []
  end

  test "a broken oracle is a test error even when no_crash is declared", %{path: path} do
    broken_oracle =
      Havoc.Oracle.custom(:broken, fn _observation, _payload ->
        raise "oracle implementation failed"
      end)

    assert_raise RuntimeError, "oracle implementation failed", fn ->
      Property.check!(
        StreamData.constant("safe"),
        [
          property_id: "Example:broken-oracle",
          property_name: "broken oracle",
          module: __MODULE__,
          oracles: [:no_crash, broken_oracle],
          corpus_path: path
        ],
        fn _payload -> %{status: 200} end
      )
    end

    assert Havoc.Corpus.load(path: path) == []
  end

  test "emits conventional property span telemetry", %{path: path} do
    events = [
      [:core, :havoc, :property, :start],
      [:core, :havoc, :property, :stop]
    ]

    handler_id = {__MODULE__, self(), make_ref()}
    :ok = :telemetry.attach_many(handler_id, events, &__MODULE__.handle_event/4, self())
    on_exit(fn -> :telemetry.detach(handler_id) end)

    assert :ok =
             Property.check!(
               StreamData.constant("safe"),
               [
                 property_id: "Example:telemetry",
                 property_name: "telemetry",
                 module: __MODULE__,
                 oracles: [:no_500],
                 corpus_path: path,
                 runs: 1
               ],
               fn _payload -> %{status: 200} end
             )

    assert_receive {:telemetry, [:core, :havoc, :property, :start], start_measurements, metadata}
    assert is_integer(start_measurements.monotonic_time)
    assert metadata.property_id == "Example:telemetry"

    assert_receive {:telemetry, [:core, :havoc, :property, :stop], stop_measurements,
                    stop_metadata}

    assert is_integer(stop_measurements.duration)
    assert stop_metadata.outcome == :ok
    assert stop_metadata.random_runs == 1
  end

  @doc false
  def handle_event(event, measurements, metadata, parent) do
    send(parent, {:telemetry, event, measurements, metadata})
  end
end
