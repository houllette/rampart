defmodule Core.TestScopePolicy do
  @behaviour Core.Scope.Policy

  @impl true
  def authorized?(target, allowed), do: target in allowed
end

defmodule Core.ScopeTest do
  use ExUnit.Case, async: true

  alias Core.Scope
  alias Core.Scope.Error

  test "denies absent and invalid policies" do
    absent_policy = Application.get_env(:security_core, :test_absent_policy)

    refute Scope.authorized?("192.0.2.1", absent_policy)
    refute Scope.authorized?("192.0.2.1", :not_a_policy)
    assert_raise Error, fn -> Scope.ensure_authorized!("192.0.2.1", absent_policy) end
  end

  test "dispatches policy state and functions" do
    policy = {Core.TestScopePolicy, ["192.0.2.1"]}

    assert Scope.authorized?("192.0.2.1", policy)
    refute Scope.authorized?("192.0.2.2", policy)
    assert Scope.authorized?("192.0.2.1", &(&1 == "192.0.2.1"))
  end

  test "authorizes every target before guarded code runs" do
    parent = self()
    policy = {Core.TestScopePolicy, ["192.0.2.1"]}

    assert_raise Error, fn ->
      Scope.ensure_all_authorized!(["192.0.2.1", "192.0.2.2"], policy)
      send(parent, :launched)
    end

    refute_received :launched
  end

  test "guarded launch emits the shared audit event before invoking the function" do
    handler_id = {__MODULE__, self()}

    :telemetry.attach(
      handler_id,
      [:core, :portico, :launch],
      &__MODULE__.handle_event/4,
      self()
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    assert :launched =
             Scope.guarded_launch(
               :portico,
               "192.0.2.1",
               fn target -> target == "192.0.2.1" end,
               fn ->
                 :launched
               end
             )

    assert_receive {:telemetry, [:core, :portico, :launch], %{}, %{target: "192.0.2.1"}}
  end

  @doc false
  def handle_event(event, measurements, metadata, parent) do
    send(parent, {:telemetry, event, measurements, metadata})
  end
end
