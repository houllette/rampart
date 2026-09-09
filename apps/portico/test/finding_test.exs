defmodule Portico.FindingTest do
  use ExUnit.Case, async: true

  alias Core.Finding
  alias Portico.{Host, Port, Service}

  test "projects one stable Core finding per open port" do
    observed_at = ~U[2026-01-02 03:04:05Z]

    open_port = %Port{
      number: 443,
      protocol: :tcp,
      state: "open",
      service: %Service{name: "https", product: "nginx", version: "1.27"}
    }

    host = %Host{
      ip: "192.0.2.10",
      hostname: "web.example",
      status: :up,
      scanned_at: observed_at,
      ports: [open_port, %Port{number: 80, protocol: :tcp, state: "closed"}]
    }

    assert [finding] = Portico.to_findings(host)
    assert %Finding{source: :portico, category: :exposed_service, raw: ^open_port} = finding
    assert finding.id == Finding.dedupe_id(:portico, ["endpoint", "192.0.2.10", :tcp, 443])
    assert finding.observed_at == observed_at

    assert finding.locus == %{
             ip: "192.0.2.10",
             hostname: "web.example",
             port: 443,
             protocol: :tcp,
             service: "https",
             product: "nginx",
             version: "1.27"
           }
  end

  test "mutable service enrichment does not change endpoint identity" do
    original =
      %Host{
        ip: "192.0.2.10",
        status: :up,
        ports: [%Port{number: 443, protocol: "tcp", state: "open"}]
      }
      |> Portico.to_findings()
      |> hd()

    enriched =
      %Host{
        ip: "192.0.2.10",
        hostname: "new-name.example",
        status: :up,
        ports: [
          %Port{
            number: 443,
            protocol: :tcp,
            state: "open",
            service: %Service{name: "https", product: "changed"}
          }
        ]
      }
      |> Portico.to_findings()
      |> hd()

    assert original.id == enriched.id
    assert original.category == :open_port
    assert enriched.category == :exposed_service
  end
end
