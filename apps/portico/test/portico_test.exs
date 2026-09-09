defmodule PorticoTest do
  use ExUnit.Case, async: true

  alias Core.Scope.Error
  alias Portico.{Host, Scope.Allowlist}

  test "high-level scans are lazy and bound discovery by enrichment concurrency" do
    scope = Allowlist.new!(["10.0.0.0/24"])

    stream =
      Portico.scan("10.0.0.0/24", scope: scope)
      |> Portico.discover(engine: Portico.TestDiscoveryEngine, observer: self(), count: 10)
      |> Portico.enrich(
        engine: Portico.TestEnrichmentEngine,
        observer: self(),
        block: true,
        max_concurrency: 2
      )
      |> Portico.stream()

    refute_receive {:discovery_started, _target}

    consumer = Task.async(fn -> Enum.take(stream, 1) end)

    assert_receive {:discovery_started, "10.0.0.0/24"}
    assert_receive {:enrichment_started, first_worker, [_first_ip]}
    assert_receive {:enrichment_started, _second_worker, [_second_ip]}
    refute_receive {:enrichment_started, _third_worker, _ips}, 50

    send(first_worker, :release)
    assert [%Host{status: :up}] = Task.await(consumer)

    assert pull_count() <= 2
  end

  test "streams normalized findings without replacing native host results" do
    scope = Allowlist.new!(["10.0.0.0/24"])

    findings =
      Portico.scan("10.0.0.1", scope: scope)
      |> Portico.discover(engine: Portico.TestDiscoveryEngine, observer: self(), count: 1)
      |> Portico.enrich(engine: Portico.TestEnrichmentEngine, observer: self())
      |> Portico.findings()
      |> Enum.to_list()

    assert [%Core.Finding{source: :portico, locus: %{ip: "10.0.0.1", port: 443}}] = findings
  end

  test "authorizes every requested target before invoking a discovery engine" do
    parent = self()

    policy = fn target, _context -> target.value == "10.0.0.1" end

    scan =
      Portico.scan(["10.0.0.1", "10.0.0.2"], scope: policy)
      |> Portico.discover(engine: Portico.TestDiscoveryEngine, observer: parent)
      |> Portico.enrich(engine: Portico.TestEnrichmentEngine, observer: parent)
      |> Portico.stream()

    assert_raise Error, fn -> Enum.to_list(scan) end
    refute_receive {:discovery_started, _target}
  end

  test "fails closed when no scope policy is configured" do
    scan =
      Portico.scan("10.0.0.1")
      |> Portico.discover(engine: Portico.TestDiscoveryEngine, observer: self())
      |> Portico.enrich(engine: Portico.TestEnrichmentEngine, observer: self())
      |> Portico.stream()

    assert_raise Error, fn -> Enum.to_list(scan) end
    refute_receive {:discovery_started, _target}
  end

  test "validates generic and engine-specific options when building a plan" do
    scope = Allowlist.new!(["10.0.0.0/24"])
    scan = Portico.scan("10.0.0.1", scope: scope)

    assert_raise NimbleOptions.ValidationError, fn ->
      Portico.discover(scan, engine: Portico.TestDiscoveryEngine, observer: self(), unknown: true)
    end

    scan = Portico.discover(scan, engine: Portico.TestDiscoveryEngine, observer: self())

    assert_raise NimbleOptions.ValidationError, fn ->
      Portico.enrich(scan,
        engine: Portico.TestEnrichmentEngine,
        observer: self(),
        max_concurrency: 0
      )
    end
  end

  defp pull_count(count \\ 0) do
    receive do
      {:discovery_pull, _index} -> pull_count(count + 1)
    after
      0 -> count
    end
  end
end
