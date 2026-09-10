defmodule RampartIAST.ArgumentTest do
  use ExUnit.Case, async: true

  alias RampartIAST.{Argument, Limits}

  test "inspects maps, tuples, improper lists and exact binary capacity" do
    limits = Limits.new!([])
    term = %{key: {"prefix-marker", ["other" | "marker"]}}
    assert {bytes, true, []} = Argument.inspect_marker(term, "marker", limits)
    assert bytes == :erlang.external_size(term)

    assert {6, true, []} =
             Argument.inspect_marker("marker", "marker", %{limits | max_argument_bytes: 6})

    assert {_bytes, false, [:argument_bytes]} =
             Argument.inspect_marker("marker!", "marker", %{limits | max_argument_bytes: 6})
  end

  test "does not size closures or expand wide containers before enforcing structural limits" do
    captured = List.duplicate(:value, 100_000)

    assert {_bytes, false, [:unsupported_argument]} =
             Argument.inspect_marker(fn -> captured end, "marker", Limits.new!([]))

    assert {_bytes, false, [:argument_terms]} =
             Argument.inspect_marker(
               List.to_tuple(captured),
               "marker",
               Limits.new!(max_argument_terms: 4)
             )
  end
end
