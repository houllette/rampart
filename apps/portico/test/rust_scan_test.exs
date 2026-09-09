defmodule Portico.TestChunkRunner do
  @behaviour Core.Runner

  @impl true
  def stream(_command, opts), do: Keyword.fetch!(opts, :chunks)

  @impl true
  def run(_command, _opts), do: {"", 0}
end

defmodule Portico.RustScanTest do
  use ExUnit.Case, async: true

  alias Portico.Discovery.Result
  alias Portico.Discovery.RustScan
  alias Portico.Engine.OutputError
  alias Portico.Target

  test "parses partial greppable lines and consumes stderr separately" do
    target = Target.parse!("192.0.2.0/24")

    opts = [
      runner: Portico.TestChunkRunner,
      runner_options: [
        chunks: [
          {:stdout, "RustScan banner\n192.0."},
          {:stderr, "warning"},
          {:stdout, "2.10 -> [22, 443]\n192.0.2.11 -> [8080"},
          {:stdout, "]\n"}
        ]
      ]
    ]

    assert [
             %Result{target: ^target, ip: "192.0.2.10", ports: [22, 443]},
             %Result{target: ^target, ip: "192.0.2.11", ports: [8080]}
           ] = Enum.to_list(RustScan.stream(target, opts))
  end

  test "raises on a drifted line that looks like greppable output" do
    target = Target.parse!("192.0.2.1")

    stream =
      RustScan.stream(target,
        runner: Portico.TestChunkRunner,
        runner_options: [chunks: ["oops -> ports"]]
      )

    assert_raise OutputError, fn -> Enum.to_list(stream) end
  end

  test "builds a scanner-only command without RustScan's nmap passthrough" do
    target = Target.parse!("192.0.2.0/24")
    opts = NimbleOptions.validate!([ports: [443, 22], batch_size: 100], RustScan.option_schema())

    command = RustScan.command(target, opts)

    assert command == [
             "rustscan",
             "--addresses",
             "192.0.2.0/24",
             "--greppable",
             "--batch-size",
             "100",
             "--timeout",
             "1500",
             "--tries",
             "1",
             "--ports",
             "22,443"
           ]

    refute "--" in command
  end
end
