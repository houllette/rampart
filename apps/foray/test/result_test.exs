defmodule Foray.ResultTest do
  use ExUnit.Case, async: true

  alias Core.{Finding, Seed}
  alias Foray.Result

  test "round-trips the versioned Foray finding schema" do
    finding = %Finding{
      id: "foray:abc",
      source: :foray,
      category: :param_injection,
      locus: %{
        url: "https://app.example/search?q=admin",
        method: "GET",
        host: "app.example",
        param: "q",
        keyword: "FUZZ",
        input: "admin",
        status: 200,
        length: 42,
        words: 2,
        lines: 1,
        content_type: "text/plain"
      },
      severity: nil,
      confidence: :medium,
      evidence: "matched",
      raw: %{"status" => 200},
      seed: %Seed{
        id: "seed-1",
        value: "admin",
        classes: [:sqli],
        provenance: :counterexample,
        origin: {:havoc, "finding-1"},
        meta: %{"source" => "test"}
      },
      observed_at: ~U[2026-01-02 03:04:05Z]
    }

    json = Result.encode!(finding)

    assert {:ok, ^finding} = Result.decode(json)
    assert {:ok, map} = Jason.decode(json)
    assert map["schema_version"] == 1
  end

  test "rejects unknown schema versions" do
    assert {:error, {:unsupported_schema_version, 99}} = Result.decode(~s({"schema_version":99}))
  end
end
