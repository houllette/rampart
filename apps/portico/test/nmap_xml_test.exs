defmodule Portico.NmapXMLTest do
  use ExUnit.Case, async: true

  alias Core.Runner.Exile, as: ExileRunner
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

  test "document byte limits apply to complete and streamed documents and close the input" do
    xml = "<nmaprun><host/></nmaprun>"

    assert {:ok, [_host]} =
             NmapXML.parse_string(xml, limits: [max_document_bytes: byte_size(xml)])

    parent = self()

    stream =
      Stream.resource(
        fn -> [xml] end,
        fn
          [chunk] -> {[chunk], []}
          [] -> {:halt, []}
        end,
        fn _ -> send(parent, :closed) end
      )

    assert {:error, {:xml_limit, :max_document_bytes, 1}} =
             NmapXML.parse_stream(stream, limits: [max_document_bytes: 1])

    assert_received :closed

    assert {:error, {:xml_limit, :max_document_bytes, 1}} =
             NmapXML.parse_string(xml, limits: [max_document_bytes: 1])
  end

  test "structure budgets reject excessive small events instead of returning partial hosts" do
    for {key, xml} <- [
          max_hosts: "<nmaprun><host/><host/></nmaprun>",
          max_ports: "<nmaprun><host><ports><port/><port/></ports></host></nmaprun>",
          max_scripts: "<nmaprun><host><script/><script/></host></nmaprun>",
          max_script_nodes: "<nmaprun><host><script><elem/><elem/></script></host></nmaprun>",
          max_elements: "<nmaprun><ignored/></nmaprun>",
          max_depth: "<nmaprun><host/></nmaprun>"
        ] do
      assert {:error, {:xml_limit, ^key, 1}} = NmapXML.parse_string(xml, limits: [{key, 1}])
    end
  end

  test "decoded text and scalar budgets include attributes, entities and accumulated chunks" do
    assert {:error, {:xml_limit, :max_text_bytes, 3}} =
             NmapXML.parse_string("<nmaprun><host><script output='abcd'/></host></nmaprun>",
               limits: [max_text_bytes: 3]
             )

    xml =
      "<nmaprun><host><script><elem>" <>
        String.duplicate("&#65;", 40) <>
        "</elem></script></host></nmaprun>"

    chunks = for <<byte <- xml>>, do: <<byte>>

    assert {:error, {:xml_limit, :max_scalar_bytes, 32}} =
             NmapXML.parse_stream(chunks, limits: [max_scalar_bytes: 32])

    assert {:error, {:xml_limit, :max_scalar_bytes, 32}} =
             NmapXML.parse_string(
               "<nmaprun><host><script output='" <>
                 String.duplicate("A", 33) <>
                 "'/></host></nmaprun>",
               limits: [max_scalar_bytes: 32]
             )
  end

  test "host limits remain cumulative when collection is disabled" do
    assert {:error, {:xml_limit, :max_hosts, 1}} =
             NmapXML.parse_string("<nmaprun><host/><host/></nmaprun>",
               collect: false,
               limits: [max_hosts: 1]
             )
  end

  test "scalar accounting remains attached to its node across nested output" do
    xml =
      "<nmaprun><host><script><elem>" <>
        String.duplicate("A", 20) <>
        "<elem>child</elem>" <>
        String.duplicate("B", 20) <>
        "</elem></script></host></nmaprun>"

    assert {:error, {:xml_limit, :max_scalar_bytes, 32}} =
             NmapXML.parse_string(xml, limits: [max_scalar_bytes: 32])

    assert {:ok, [%Host{scripts: [%Script{data: [%Node{value: value, children: [child]}]}]}]} =
             NmapXML.parse_string(xml, limits: [max_scalar_bytes: 40])

    assert value == String.duplicate("A", 20) <> String.duplicate("B", 20)
    assert child.value == "child"
  end

  test "exact decoded budgets preserve values under character-by-character input" do
    xml = "<nmaprun><host><script output='ab'><elem>cd</elem></script></host></nmaprun>"

    options = [
      scanned_at: ~U[2026-01-02 03:04:05Z],
      limits: [max_text_bytes: 4, max_scalar_bytes: 2]
    ]

    assert {:ok, [%Host{scripts: [%Script{output: "ab", data: [%Node{value: "cd"}]}]}]} =
             NmapXML.parse_string(xml, options)

    assert NmapXML.parse_stream(for(<<byte <- xml>>, do: <<byte>>), options) ==
             NmapXML.parse_string(xml, options)

    assert {:error, {:xml_limit, :max_text_bytes, 3}} =
             NmapXML.parse_string(xml, limits: [max_text_bytes: 3])
  end

  @tag :requires_native_process
  @tag :tmp_dir
  test "a parser limit reaps a native stream owner", %{tmp_dir: tmp_dir} do
    pid_file = Path.join(tmp_dir, "xml.pid")

    command = [
      "sh",
      "-c",
      ~s(echo $$ > "$1"; printf '<nmaprun><host/><host/>'; exec sleep 30),
      "xml-limit",
      pid_file
    ]

    chunks =
      ExileRunner.stream(command, stderr: :consume, exit_timeout: 200, ignore_epipe: true)
      |> Stream.map(fn {:stdout, chunk} -> chunk end)

    assert {:error, {:xml_limit, :max_hosts, 1}} =
             NmapXML.parse_stream(chunks, limits: [max_hosts: 1])

    pid = pid_file |> File.read!() |> String.trim()
    assert {_output, status} = System.cmd("kill", ["-0", pid], stderr_to_stdout: true)
    assert status != 0
  end
end
