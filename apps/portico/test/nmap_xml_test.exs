defmodule Portico.NmapXMLTest do
  use ExUnit.Case, async: true

  alias Portico.{Host, NmapXML, OSClass, OSMatch, Port, Script, Script.Node, Service}

  @fixture Path.expand("fixtures/nmap_host.xml", __DIR__)

  test "stream-parses host, service, scripts, and OS fingerprints across tiny chunks" do
    stream = File.stream!(@fixture, 17, [])
    scanned_at = ~U[2026-01-02 03:04:05Z]

    assert {:ok,
            [
              %Host{
                ip: "192.0.2.10",
                hostname: "web.example",
                status: :up,
                scanned_at: ^scanned_at,
                scripts: [%Script{id: "uptime", output: "10 days"}],
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
                        data: [
                          %Node{
                            type: :table,
                            key: "subject",
                            children: [
                              %Node{
                                type: :element,
                                key: "commonName",
                                value: "web.example"
                              }
                            ]
                          }
                        ]
                      }
                    ]
                  }
                ],
                os_matches: [
                  %OSMatch{
                    name: "Linux 5.15",
                    accuracy: 98,
                    classes: [
                      %OSClass{
                        family: "Linux",
                        generation: "5.X",
                        accuracy: 98,
                        cpes: ["cpe:/o:linux:linux_kernel:5"]
                      }
                    ]
                  }
                ]
              }
            ]} = NmapXML.parse_stream(stream, scanned_at: scanned_at)
  end

  test "invokes the host callback without retaining hosts when collection is disabled" do
    parent = self()

    assert {:ok, []} =
             NmapXML.parse_stream(File.stream!(@fixture, 64, []),
               collect: false,
               on_host: fn host ->
                 send(parent, {:host, host.ip})
                 :ok
               end
             )

    assert_receive {:host, "192.0.2.10"}
  end
end
