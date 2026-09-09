defmodule Havoc.CaseTest do
  use ExUnit.Case, async: true
  use Havoc.Case

  security_property "binds payload and runs declared oracles through havoc_assert",
    generator: StreamData.constant("<havoc-marker>"),
    oracles: [:no_500, :no_reflection],
    persist: false,
    replay: false,
    runs: 1 do
    response = %{status: 200, body: "safe", content_type: "text/html"}
    havoc_assert(response, payload)
  end

  security_property "automatically treats the body result as the observation",
    generator: StreamData.constant("'"),
    oracles: [:no_injection_signal],
    persist: false,
    replay: false,
    runs: 1 do
    %{body: "invalid input"}
  end

  test "use Havoc.Case imports adversarial generator helpers" do
    assert Enum.take(injection([:sqli]), 1) |> Enum.all?(&is_binary/1)
  end
end
