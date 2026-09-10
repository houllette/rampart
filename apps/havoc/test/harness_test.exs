defmodule Havoc.HarnessTest do
  use ExUnit.Case, async: true

  alias Havoc.Harness
  alias Havoc.Harness.{Binding, Error, Plan, Result}

  defp plan do
    Plan.new!(%{
      "id" => "stateful-counter.v1",
      "description" => "apply a generated delta and observe the resulting counter",
      "steps" => [
        %{
          "id" => "positive-control",
          "operation" => "read",
          "role" => "positive_control",
          "arguments" => %{}
        },
        %{
          "id" => "candidate-write",
          "operation" => "increment",
          "role" => "candidate",
          "arguments" => %{"delta" => %{"$payload" => ["delta"]}}
        },
        %{
          "id" => "candidate-read",
          "operation" => "read",
          "role" => "observation",
          "arguments" => %{}
        }
      ],
      "meta" => %{"fixture" => "counter"}
    })
  end

  defp binding(plan, owner, overrides \\ []) do
    operations = %{
      "read" => fn state, _arguments -> {:ok, state, %{count: state.count}} end,
      "increment" => fn state, %{"delta" => delta} ->
        next = %{state | count: state.count + delta}
        {:ok, next, %{count: next.count, delta: delta}}
      end
    }

    Binding.new!(
      plan,
      Keyword.merge(
        [
          setup: fn _payload -> {:ok, %{count: 0}} end,
          operations: operations,
          teardown: fn state ->
            send(owner, {:torn_down, state})
            :ok
          end
        ],
        overrides
      )
    )
  end

  test "executes a finite reviewed scenario and resolves inert payload references" do
    plan = plan()
    binding = binding(plan, self())

    assert %Result{} = result = Harness.execute(binding, %{"delta" => 3})
    assert result.plan_id == plan.id
    assert result.plan_sha256 == plan.sha256
    assert result.completed_steps == 3

    assert Enum.map(result.observations, &{&1.step_id, &1.value}) == [
             {"positive-control", %{count: 0}},
             {"candidate-write", %{count: 3, delta: 3}},
             {"candidate-read", %{count: 3}}
           ]

    assert [%{value: %{count: 3, delta: 3}}] = Result.observations(result, :candidate)
    assert_receive {:torn_down, %{count: 3}}
  end

  test "the same reviewed plan and payload produce the same replay shape" do
    binding = binding(plan(), self())
    first = Harness.execute(binding, %{delta: 2})
    second = Harness.execute(binding, %{delta: 2})

    assert first == second
    assert_receive {:torn_down, %{count: 2}}
    assert_receive {:torn_down, %{count: 2}}
  end

  test "model-shaped plans cannot carry callbacks or unreviewed operations" do
    attributes = plan() |> Plan.to_map() |> Map.drop(["schema_version", "sha256"])
    [first | rest] = attributes["steps"]

    assert_raise ArgumentError, ~r/exactly/, fn ->
      Plan.new!(Map.put(attributes, "execute", "System.cmd"))
    end

    unsafe = Map.put(attributes, "steps", [Map.put(first, "callback", "run") | rest])
    assert_raise ArgumentError, ~r/step must contain exactly/, fn -> Plan.new!(unsafe) end

    assert_raise ArgumentError, ~r/missing reviewed operations/, fn ->
      Binding.new!(plan(),
        setup: fn _ -> {:ok, %{}} end,
        operations: %{"read" => fn state, _ -> {:ok, state, nil} end},
        teardown: fn _ -> :ok end
      )
    end
  end

  test "teardown runs when a step fails and Havoc treats the fixture failure as inconclusive" do
    plan = plan()

    operations = %{
      "read" => fn state, _arguments -> {:ok, state, %{count: state.count}} end,
      "increment" => fn _state, _arguments -> {:error, :injected_failure} end
    }

    binding =
      Binding.new!(plan,
        setup: fn _ -> {:ok, %{count: 0}} end,
        operations: operations,
        teardown: fn state ->
          send(self(), {:wrong_owner, state})
          :ok
        end
      )

    # Capture the test process explicitly; callbacks may execute under a validator task later.
    owner = self()

    binding = %{
      binding
      | teardown: fn state ->
          send(owner, {:torn_down, state})
          :ok
        end
    }

    assert_raise Error, ~r/injected_failure/, fn -> Harness.execute(binding, %{"delta" => 1}) end
    assert_receive {:torn_down, %{count: 0}}

    seed = %Core.Seed{id: "scenario-failure", value: %{"delta" => 1}, provenance: :external}

    assert %{verdict: :inconclusive, findings: []} =
             Havoc.validate(seed, Harness.target(binding),
               oracles: [
                 Havoc.Oracle.custom(:never_reached, fn _observation, _payload -> :ok end)
               ],
               persist: false
             )

    assert_receive {:torn_down, %{count: 0}}
  end

  test "a callback that returns after the soft deadline fails and still tears down" do
    plan =
      Plan.new!(%{
        "id" => "deadline.v1",
        "description" => "check the deadline after a reviewed callback returns",
        "steps" => [
          %{
            "id" => "slow",
            "operation" => "slow",
            "role" => "candidate",
            "arguments" => %{}
          }
        ],
        "meta" => %{}
      })

    owner = self()

    binding =
      Binding.new!(plan,
        setup: fn _ -> {:ok, :state} end,
        operations: %{
          "slow" => fn state, _arguments ->
            Process.sleep(10)
            {:ok, state, :completed}
          end
        },
        teardown: fn state ->
          send(owner, {:torn_down, state})
          :ok
        end,
        max_execution_ms: 1
      )

    assert_raise Error, ~r/execution_deadline/, fn -> Harness.execute(binding, %{}) end
    assert_receive {:torn_down, :state}
  end

  test "observation overflow cannot become a security confirmation" do
    plan =
      Plan.new!(%{
        "id" => "large-observation.v1",
        "description" => "emit bounded evidence",
        "steps" => [
          %{
            "id" => "observe",
            "operation" => "observe",
            "role" => "observation",
            "arguments" => %{}
          }
        ],
        "meta" => %{}
      })

    binding =
      Binding.new!(plan,
        setup: fn _ -> {:ok, :state} end,
        operations: %{
          "observe" => fn state, _arguments ->
            {:ok, state, String.duplicate("x", 2_000)}
          end
        },
        teardown: fn _ -> :ok end,
        max_observation_bytes: 128
      )

    seed = %Core.Seed{id: "overflow", value: %{}, provenance: :external}

    assert %{verdict: :inconclusive, findings: []} =
             Havoc.validate(seed, Harness.target(binding),
               oracles: [Havoc.Oracle.custom(:bounded, fn _observation, _payload -> :ok end)],
               persist: false
             )
  end
end
