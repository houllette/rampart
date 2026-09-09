defmodule Portico.ResultSerializationTest do
  use ExUnit.Case, async: true

  alias Portico.{Host, Hostname, OSClass, OSMatch, Port, Result, Script, Script.Node, Service}

  test "round-trips the versioned host schema through Jason" do
    scanned_at = ~U[2026-01-02 03:04:05.123456Z]

    host = %Host{
      ip: "192.0.2.10",
      hostname: "web.example",
      hostnames: [%Hostname{name: "web.example", type: "PTR"}],
      status: :up,
      scanned_at: scanned_at,
      addresses: %{"ipv4" => "192.0.2.10"},
      ports: [
        %Port{
          number: 443,
          protocol: :tcp,
          state: "open",
          reason: "syn-ack",
          service: %Service{
            name: "https",
            product: "nginx",
            version: "1.27",
            confidence: 10,
            cpes: ["cpe:/a:igor_sysoev:nginx:1.27"]
          },
          scripts: [
            %Script{
              id: "ssl-cert",
              output: "certificate",
              data: [%Node{type: :element, key: "subject", value: "CN=web.example"}]
            }
          ]
        }
      ],
      os_matches: [
        %OSMatch{
          name: "Linux",
          accuracy: 98,
          classes: [%OSClass{family: "Linux", accuracy: 98, cpes: ["cpe:/o:linux:linux_kernel"]}]
        }
      ],
      meta: %{"source" => "test"}
    }

    json = Result.encode!(host)

    assert {:ok, ^host} = Result.decode(json)
    assert {:ok, decoded_map} = Jason.decode(json)
    assert decoded_map["schema_version"] == Host.schema_version()
    assert decoded_map["ports"] |> hd() |> get_in(["service", "name"]) == "https"
  end

  test "rejects unsupported persisted schema versions" do
    assert {:error, {:unsupported_schema_version, 99}} =
             Result.decode(~s({"schema_version":99}))
  end
end
