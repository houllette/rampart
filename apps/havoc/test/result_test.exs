defmodule Havoc.ResultTest do
  use ExUnit.Case, async: true

  test "round-trips Havoc findings through the versioned persistence schema" do
    observed_at = DateTime.utc_now()

    seed = %Core.Seed{
      id: "seed",
      value: %{role: :outsider, payload: <<0, 255>>},
      classes: [:authz_invariant],
      provenance: :counterexample,
      origin: {:havoc, "finding"},
      meta: %{property_id: "Authz:property"}
    }

    finding = %Core.Finding{
      id: "finding",
      source: :havoc,
      category: :authz_bypass,
      locus: %{module: "AuthzTest", function: "authorize/2", property: "denies outsiders"},
      severity: nil,
      confidence: :high,
      evidence: "authorization invariant failed",
      raw: %{payload: seed.value, observation: {:ok, 200}},
      seed: seed,
      observed_at: observed_at
    }

    assert {:ok, decoded} = finding |> Havoc.Result.encode!() |> Havoc.Result.decode()
    assert decoded == finding
  end

  test "rejects unknown enums and unsupported schema versions" do
    finding = %Core.Finding{
      id: "finding",
      source: :havoc,
      category: :crash,
      locus: %{},
      confidence: :high,
      evidence: "crashed",
      observed_at: DateTime.utc_now()
    }

    document = finding |> Havoc.Result.encode!() |> Jason.decode!()

    assert {:error, {:unsupported_schema_version, 2}} =
             document
             |> Map.put("schema_version", 2)
             |> Jason.encode!()
             |> Havoc.Result.decode()

    assert {:error, {:invalid_finding, {:invalid_enum, "invented"}}} =
             document
             |> Map.put("category", "invented")
             |> Jason.encode!()
             |> Havoc.Result.decode()
  end
end
