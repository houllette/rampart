defmodule Foray.NDJSONTest do
  use ExUnit.Case, async: true

  alias Foray.{Match, NDJSON, OutputError}

  @fixture Path.expand("fixtures/ffuf_v2_2.ndjson", __DIR__)

  test "streams ffuf v2.2 records across arbitrary chunk boundaries" do
    ndjson = File.read!(@fixture)

    chunks = [
      binary_part(ndjson, 0, 37),
      binary_part(ndjson, 37, 101),
      binary_part(ndjson, 138, byte_size(ndjson) - 138)
    ]

    assert [first, second] = Enum.to_list(NDJSON.stream(chunks))
    assert %Match{input: %{"FUZZ" => "admin"}, status: 200, duration_ns: 125_000_000} = first
    assert %Match{input: %{"FUZZ" => "login"}, status: 301, redirect_location: "/login/"} = second
    assert first.raw["content-type"] == "text/html"
  end

  test "fails visibly on malformed stdout instead of silently dropping format drift" do
    assert_raise OutputError, fn -> Enum.to_list(NDJSON.stream(["ffuf banner on stdout\n"])) end
  end

  test "rejects records with invalid Base64 input values" do
    line =
      ~s({"input":{"FUZZ":"not base64"},"position":1,"status":200,"length":1,"words":1,"lines":1,"content-type":"text/plain","redirectlocation":"","url":"https://app.example/x","duration":1,"scraper":{},"resultfile":"","host":"app.example"})

    assert {:error, %OutputError{reason: {:invalid_base64_input, "FUZZ"}}} =
             NDJSON.parse_line(line)
  end

  test "complete lines and direct parsing enforce raw bytes before whitespace or decoding" do
    line = String.duplicate(" ", 1_048_577)
    assert {:error, %OutputError{reason: :line_too_long, line: preview}} = NDJSON.parse_line(line)
    assert byte_size(preview) <= 1_024

    for suffix <- ["", "\n"], split <- [1, 65_535, 1_048_576] do
      input = line <> suffix
      chunks = [binary_part(input, 0, split), binary_part(input, split, byte_size(input) - split)]
      error = assert_raise OutputError, fn -> Enum.to_list(NDJSON.stream(chunks)) end
      assert error.reason == :line_too_long
      assert byte_size(error.line) <= 1_024
    end
  end

  test "exact raw limits account for CRLF and retain valid records across tiny chunks" do
    record = @fixture |> File.read!() |> String.split("\n") |> hd()
    padded = record <> String.duplicate(" ", 1_048_575 - byte_size(record))
    assert {:ok, expected} = NDJSON.parse_line(padded <> "\r\n")
    assert [^expected] = Enum.to_list(NDJSON.stream([padded, "\r", "\n"]))
    assert [^expected] = Enum.to_list(NDJSON.stream([padded <> " "]))
    assert {:error, %OutputError{reason: :line_too_long}} = NDJSON.parse_line(padded <> " \r\n")
  end
end
