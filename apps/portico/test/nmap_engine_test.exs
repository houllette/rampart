defmodule Portico.TestNmapRunner do
  @behaviour Core.Runner

  @impl true
  def stream(command, opts) do
    if observer = opts[:observer], do: send(observer, {:command, command})
    Keyword.fetch!(opts, :chunks)
  end

  @impl true
  def run(_command, _opts), do: {"", 0}
end

defmodule Portico.TestSlowRunner do
  @behaviour Core.Runner

  @impl true
  def stream(_command, _opts) do
    Stream.resource(
      fn -> :waiting end,
      fn state ->
        Process.sleep(5_000)
        {["never"], state}
      end,
      fn _state -> :ok end
    )
  end

  @impl true
  def run(_command, _opts), do: {"", 0}
end

defmodule Portico.NmapEngineTest do
  use ExUnit.Case, async: true

  alias Portico.Discovery.Result
  alias Portico.Enrichment.Nmap
  alias Portico.Host

  @fixture Path.expand("fixtures/nmap_host.xml", __DIR__)

  test "runs nmap with structured options and aligns parsed hosts" do
    xml = File.read!(@fixture)
    entry = %Result{ip: "192.0.2.10", ports: [443]}

    opts = [
      runner: Portico.TestNmapRunner,
      runner_options: [
        observer: self(),
        chunks: [binary_part(xml, 0, 111), binary_part(xml, 111, byte_size(xml) - 111)]
      ],
      scripts: ["default", "ssl-cert"],
      os_detection: true,
      timing_template: 4,
      resolve_dns: :never
    ]

    assert {:ok, [%Host{ip: "192.0.2.10", status: :up, ports: [port]}]} =
             Nmap.enrich([entry], opts)

    assert port.number == 443

    assert_receive {:command, command}
    assert ["nmap", "-sT" | _rest] = command

    assert Enum.chunk_every(command, 2, 1, :discard)
           |> Enum.any?(&(&1 == ["--script", "default,ssl-cert"]))

    assert List.last(command) == "192.0.2.10"
  end

  test "XML budget errors survive the engine boundary without aligning partial hosts" do
    xml = "<nmaprun><host/><host/></nmaprun>"
    entry = %Result{ip: "192.0.2.10", ports: [443]}

    assert {:error, {:xml_parse_error, {:xml_limit, :max_hosts, 1}}} =
             Nmap.enrich([entry],
               runner: Portico.TestNmapRunner,
               runner_options: [chunks: [xml]],
               xml_limits: [max_hosts: 1]
             )
  end

  @tag :requires_native_process
  @tag :tmp_dir
  test "native limit cleanup retains its cause and normal nonzero completion remains an error", %{
    tmp_dir: tmp_dir
  } do
    executable = Path.join(tmp_dir, "nmap")

    File.write!(executable, """
    #!/bin/sh
    echo $$ > "$(dirname "$0")/pid"
    printf '<nmaprun><host/><host/>'
    exec sleep 30
    """)

    File.chmod!(executable, 0o755)
    entry = %Result{ip: "192.0.2.10", ports: [443]}

    assert {:error, {:xml_parse_error, {:xml_limit, :max_hosts, 1}}} =
             Nmap.enrich([entry],
               executable: executable,
               exit_timeout: 200,
               xml_limits: [max_hosts: 1]
             )

    pid = tmp_dir |> Path.join("pid") |> File.read!() |> String.trim()
    {_output, status} = System.cmd("kill", ["-0", pid], stderr_to_stdout: true)
    assert status != 0

    File.write!(executable, "#!/bin/sh\nprintf '<nmaprun><host/></nmaprun>'\nexit 7\n")

    assert {:error, {:runner_exit, reason}} = Nmap.enrich([entry], executable: executable)
    assert inspect(reason) =~ "7"
  end

  test "returns a typed timeout host and kills the owner task" do
    entry = %Result{ip: "192.0.2.20", ports: [80]}

    assert {:ok, [%Host{ip: "192.0.2.20", status: :timeout}]} =
             Nmap.enrich([entry], runner: Portico.TestSlowRunner, timeout: 10)
  end

  test "rejects a batch that would broaden the discovered port set" do
    first = %Result{ip: "192.0.2.10", ports: [80]}
    second = %Result{ip: "192.0.2.11", ports: [443]}

    assert {:error, :batch_requires_identical_ports_and_protocol} =
             Nmap.enrich([first, second], runner: Portico.TestNmapRunner)
  end

  test "rejects target-like output and protocol broadening" do
    invalid_target = %Result{ip: "-iL", ports: [80]}
    tcp_result = %Result{ip: "192.0.2.10", ports: [53], protocol: :tcp}

    assert {:error, :invalid_discovery_result} =
             Nmap.enrich([invalid_target], runner: Portico.TestNmapRunner)

    assert {:error, :scan_type_protocol_mismatch} =
             Nmap.enrich([tcp_result], runner: Portico.TestNmapRunner, scan_type: :udp)
  end

  test "declares raw-socket privilege requirements" do
    assert Nmap.required_privileges(scan_type: :connect) == []
    assert Nmap.required_privileges(scan_type: :syn) == [:net_raw]
    assert Nmap.required_privileges(os_detection: true) == [:net_raw]
  end
end
