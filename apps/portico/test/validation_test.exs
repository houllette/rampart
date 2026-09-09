defmodule Portico.ValidationTest do
  use ExUnit.Case, async: true

  alias Core.Validation.Result
  alias Portico.Scope.Allowlist

  defmodule ClosedEngine do
    @behaviour Portico.Enrichment.Engine

    @impl true
    def option_schema, do: []

    @impl true
    def enrich([entry], _opts) do
      {:ok,
       [
         %Portico.Host{
           ip: entry.ip,
           status: :up,
           scanned_at: DateTime.utc_now(),
           ports: []
         }
       ]}
    end
  end

  test "advertises and confirms a narrowly scoped endpoint validation" do
    assert [%Core.Validation.Action{id: "portico.endpoint-reachable.v1"} = action] =
             Portico.validation_actions()

    assert action.side_effects == :authorized_probe

    result =
      Portico.validate(candidate(),
        scope: Allowlist.new!(["192.0.2.10"]),
        engine: Portico.TestEnrichmentEngine,
        engine_options: [observer: self()]
      )

    assert %Result{verdict: :confirmed, findings: [finding], seed: seed} = result

    assert finding.locus == %{
             hostname: nil,
             ip: "192.0.2.10",
             port: 443,
             product: nil,
             protocol: :tcp,
             service: nil,
             version: nil
           }

    assert finding.seed == seed
    assert seed.value == %{ip: "192.0.2.10", port: 443, protocol: :tcp}
    assert seed.origin == {:portico, "portico:candidate"}
    assert_receive {:enrichment_started, _worker, ["192.0.2.10"]}
  end

  test "refutes a point-in-time endpoint hypothesis when the port is no longer open" do
    assert %Result{verdict: :refuted, findings: [], evidence: evidence} =
             Portico.validate(candidate(),
               scope: Allowlist.new!(["192.0.2.10"]),
               engine: ClosedEngine
             )

    assert evidence.facts.host_status == :up
    assert evidence.summary =~ "was not open"
  end

  test "validation remains fail-closed before the enrichment engine is called" do
    assert_raise Core.Scope.Error, fn ->
      Portico.validate(candidate(),
        engine: Portico.TestEnrichmentEngine,
        engine_options: [observer: self()]
      )
    end

    refute_receive {:enrichment_started, _worker, _targets}
  end

  defp candidate do
    %Core.Finding{
      id: "portico:candidate",
      source: :portico,
      category: :exposed_service,
      locus: %{ip: "192.0.2.10", port: 443, protocol: :tcp, service: "https"},
      confidence: :high,
      evidence: "443/tcp open (https)",
      observed_at: DateTime.utc_now()
    }
  end
end
