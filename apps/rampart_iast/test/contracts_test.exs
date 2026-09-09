defmodule RampartIAST.ContractsTest do
  use ExUnit.Case, async: true

  alias RampartIAST.{Limits, Sink, Source}

  test "source IDs are explicitly versioned" do
    assert_raise ArgumentError, ~r/invalid IAST source/, fn ->
      Source.new!(
        id: "unversioned-source",
        schema_version: 1,
        context: :library,
        category: :untrusted_input,
        extraction: %{type: :callback_argument, position: 1},
        boundary: :in_process,
        provenance: %{}
      )
    end
  end

  test "sink argument positions must exist in the declared MFA" do
    assert_raise ArgumentError, ~r/invalid IAST sink/, fn ->
      Sink.new!(
        id: "test.invalid-position.v1",
        schema_version: 1,
        context: :library,
        mfa: {Enum, :join, 2},
        argument_positions: [3],
        category: :test_sink,
        sanitizer_expectations: [],
        severity: :info,
        rationale: "invalid fixture",
        provenance: %{}
      )
    end
  end

  test "trace limits must remain finite and positive" do
    assert_raise ArgumentError, ~r/invalid IAST limits/, fn ->
      Limits.new!(max_events: 0)
    end
  end
end
