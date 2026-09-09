defmodule Havoc.OracleTest do
  use ExUnit.Case, async: true

  alias Havoc.Oracle

  test "no_500 detects server errors and skips observations without status" do
    assert {:error, [violation]} = Oracle.check([:no_500], %{status: 503}, "payload")
    assert violation.oracle == :no_500
    assert violation.category == :crash

    assert :ok = Oracle.check([:no_500], %{status: 422}, "payload")
    assert :ok = Oracle.check([:no_500], %{body: "no status"}, "payload")
  end

  test "no_reflection is exact and HTML-only by default" do
    payload = "<havoc-marker>"

    assert {:error, [violation]} =
             Oracle.check([:no_reflection], html_response(payload), payload)

    assert violation.oracle == :no_reflection
    assert violation.confidence == :low

    assert :ok = Oracle.check([:no_reflection], html_response("&lt;havoc-marker&gt;"), payload)

    assert :ok =
             Oracle.check(
               [:no_reflection],
               %{body: payload, content_type: "application/json"},
               payload
             )

    assert :ok = Oracle.check([:no_reflection], %{body: payload}, payload)
  end

  test "no_injection_signal recognizes specific disclosure signatures without flagging generic SQL text" do
    assert {:error, [violation]} =
             Oracle.check(
               [:no_injection_signal],
               %{body: "ORA-00933: SQL command not properly ended"},
               "'"
             )

    assert violation.category == :injection
    assert violation.confidence == :medium

    assert :ok =
             Oracle.check(
               [:no_injection_signal],
               %{body: "Read our SQL documentation and database overview"},
               "'"
             )
  end

  test "authorization invariants require an independent predicate" do
    oracle =
      Oracle.authz_invariant(fn observation, _payload ->
        observation.status in [401, 403] and observation.state_unchanged?
      end)

    assert :ok =
             Oracle.check([oracle], %{status: 403, state_unchanged?: true}, "payload")

    assert {:error, [violation]} =
             Oracle.check([oracle], %{status: 200, state_unchanged?: false}, "payload")

    assert violation.category == :authz_bypass

    assert_raise ArgumentError, ~r/independent predicate/, fn ->
      Oracle.normalize!([:authz_invariant])
    end
  end

  test "custom oracles compose with built-ins" do
    custom =
      Oracle.custom(:no_secret, fn observation, _payload ->
        if String.contains?(observation.body, "secret"),
          do: {:error, "response contained the test secret"},
          else: :ok
      end)

    assert {:error, violations} =
             Oracle.check(Oracle.compose([:no_500, custom]), %{status: 500, body: "secret"}, "x")

    assert Enum.map(violations, & &1.oracle) == [:no_500, :no_secret]
  end

  defp html_response(body) do
    %{body: body, content_type: "text/html; charset=utf-8"}
  end
end
