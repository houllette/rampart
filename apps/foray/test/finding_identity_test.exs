defmodule Foray.FindingIdentityTest do
  use ExUnit.Case, async: true

  test "binary input boundaries are unambiguous and map order is irrelevant" do
    first = %{"A" => "x\0B=y", "B" => "z"}
    second = %{"A" => "x", "B" => "y\0B=z"}
    refute finding(first).id == finding(second).id
    assert finding(first).id == finding(first |> Enum.reverse() |> Map.new()).id
  end

  test "ffuf run metadata cannot change an exact input's identity" do
    first = finding(%{"A" => "admin", "B" => "one", "FFUFHASH" => "first-run"})
    replay = finding(%{"A" => "admin", "B" => "one", "FFUFHASH" => "replay-run"})
    assert first.id == replay.id
    refute first.raw == replay.raw
    refute first.id == finding(%{"A" => "admin", "B" => "two", "FFUFHASH" => "first-run"}).id
  end

  defp finding(input) do
    raw =
      Path.join(__DIR__, "fixtures/ffuf_v2_2.ndjson")
      |> File.read!()
      |> String.split("\n", trim: true)
      |> hd()
      |> Jason.decode!()
      |> Map.put("input", Map.new(input, fn {key, value} -> {key, Base.encode64(value)} end))

    {:ok, match} = raw |> Jason.encode!() |> Foray.NDJSON.parse_line()

    [job] =
      "https://app.example/"
      |> Foray.target()
      |> Foray.fuzz_param("a", wordlist: "a.txt", keyword: "A")
      |> Foray.fuzz_param("b", wordlist: "b.txt", keyword: "B")
      |> Foray.JobBuilder.build()

    Foray.Finding.from_match(match, job)
  end
end
