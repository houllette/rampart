defmodule Portico.Discovery.LineStreamTest do
  use ExUnit.Case, async: true

  alias Portico.Discovery.LineStream
  alias Portico.Discovery.RustScan
  alias Portico.Engine.OutputError

  @limit 1_048_576

  test "rejects oversized complete and unfinished lines under different partitions" do
    for suffix <- ["", "\n"], split <- [1, 65_535, @limit] do
      line = String.duplicate("x", @limit + 1) <> suffix
      chunks = [binary_part(line, 0, split), binary_part(line, split, byte_size(line) - split)]
      parent = self()

      error =
        assert_raise OutputError, fn ->
          LineStream.transform(chunks, fn _line ->
            send(parent, :parsed)
            {:ok, :unexpected}
          end)
          |> Enum.to_list()
        end

      assert error.reason == :line_too_long
      assert byte_size(error.line) <= 1_024
      refute_received :parsed
    end
  end

  test "counts CR but excludes LF and flushes an exact-limit final line" do
    payload = String.duplicate("x", @limit - 1)
    assert [^payload] = Enum.to_list(LineStream.transform([payload, "\r", "\n"], &{:ok, &1}))
    exact = payload <> "x"
    assert [^exact] = Enum.to_list(LineStream.transform([exact], &{:ok, &1}))

    assert_raise OutputError, fn ->
      Enum.to_list(LineStream.transform([exact, "\r\n"], &{:ok, &1}))
    end
  end

  test "RustScan direct parsing applies the same raw-line bound before whitespace handling" do
    assert {:error, %OutputError{reason: :line_too_long}} =
             RustScan.parse_line(String.duplicate(" ", @limit + 1))
  end
end
