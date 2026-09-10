defmodule Foray.FindingIdentityTest do
  use ExUnit.Case, async: true

  test "binary input boundaries are unambiguous and map order is irrelevant" do
    first = %{"A" => "x\0B=y", "B" => "z"}
    second = %{"A" => "x", "B" => "y\0B=z"}
    refute finding(first).id == finding(second).id
    assert finding(first).id == finding(first |> Enum.reverse() |> Map.new()).id
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
    [job] = "https://app.example/" |> Foray.target() |> Foray.JobBuilder.build()
    Foray.Finding.from_match(match, job)
  end
end
