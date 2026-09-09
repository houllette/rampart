defmodule Core.FindingTest do
  use ExUnit.Case, async: true

  alias Core.Finding

  test "dedupe IDs are deterministic and source scoped" do
    identity = ["endpoint", "192.0.2.10", :tcp, 443]

    assert Finding.dedupe_id(:portico, identity) == Finding.dedupe_id(:portico, identity)
    refute Finding.dedupe_id(:portico, identity) == Finding.dedupe_id(:foray, identity)

    refute Finding.dedupe_id(:portico, identity) ==
             Finding.dedupe_id(:portico, List.replace_at(identity, 3, 80))
  end

  test "rejects mutable structured identity values" do
    assert_raise ArgumentError, fn ->
      Finding.dedupe_id(:portico, [%{service: "https"}])
    end
  end
end
