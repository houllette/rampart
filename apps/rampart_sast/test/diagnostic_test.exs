defmodule RampartSAST.DiagnosticTest do
  use ExUnit.Case, async: true

  alias RampartSAST.Diagnostic
  alias RampartSAST.Isolated.Result

  test "bounds combining sequences by bytes and preserves valid UTF-8" do
    message = "a" <> String.duplicate("\u0301", 10_000)
    diagnostic = diagnostic(message)

    assert byte_size(diagnostic.message) <= 4_096
    assert String.valid?(diagnostic.message)
    assert String.ends_with?(diagnostic.message, "...")
  end

  test "keeps exact-limit text and normalizes invalid UTF-8 within the same byte budget" do
    exact = String.duplicate("é", 2_048)
    assert diagnostic(exact).message == exact
    assert diagnostic(<<"before", 255, "after">>).message == "before�after"

    rendered = diagnostic(%{message: String.duplicate("\u0301", 10_000)}).message
    assert byte_size(rendered) <= 4_096
    assert String.valid?(rendered)
  end

  test "direct struct validation rejects oversized and malformed messages without echoing them" do
    for message <- [String.duplicate("x", 4_097), <<255>>] do
      value = %Diagnostic{level: :error, phase: :parse, code: :invalid_source, message: message}
      error = assert_raise ArgumentError, fn -> Diagnostic.validate!(value) end
      assert byte_size(Exception.message(error)) < 256
    end
  end

  test "a small message does not retain its larger backing binary" do
    backing = String.duplicate("x", 65_536)
    message = binary_part(backing, 0, 1_000)
    rendered = diagnostic(message).message

    assert rendered == message
    assert :binary.referenced_byte_size(rendered) == byte_size(rendered)
  end

  test "isolated failures share display bounds while preserving original-message identity" do
    message = "a" <> String.duplicate("\u0301", 10_000)
    result = Result.failure("worker_failed", message, %{})
    assert [%{"message" => rendered}] = result.diagnostics
    assert rendered == diagnostic(message).message
    assert byte_size(rendered) <= 4_096

    expected =
      :crypto.hash(:sha256, ["isolated-failure\0", "worker_failed", "\0", message])
      |> Base.encode16(case: :lower)

    assert result.inventory["id"] == expected
    refute Result.failure("worker_failed", message <> "x", %{}).inventory["id"] == expected
  end

  defp diagnostic(message),
    do: Diagnostic.new!(level: :error, phase: :parse, code: :invalid_source, message: message)
end
