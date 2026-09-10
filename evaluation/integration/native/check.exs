Code.require_file("assertions.exs", System.fetch_env!("RAMPART_GATE_SUPPORT"))

defmodule Integration.Native do
  import ExUnit.Assertions
  alias Core.Validation.{Binding, Wire}

  def run do
    File.mkdir_p!("observed")
    File.mkdir_p!("proofs")

    tools =
      for {name, version, flag} <- [
            {"rustscan", "2.4.1", "--version"},
            {"nmap", "7.99", "--version"},
            {"ffuf", "2.2.0", "-V"}
          ],
          into: %{} do
        executable =
          System.find_executable(name) || raise("required pinned executable missing: #{name}")

        {output, 0} = System.cmd(executable, [flag], stderr_to_stdout: true)
        expected = if name == "ffuf", do: "2.1.0", else: version
        assert Regex.match?(~r/(?:^|\s)#{Regex.escape(expected)}(?:\s|$)/, output)
        wrapper = observed(name, executable)

        if name == "ffuf" do
          assert :ok = Foray.Fuzz.Ffuf.validate_runtime(executable: executable)
          {name, executable}
        else
          {name, wrapper}
        end
      end

    {:ok, requests} = Agent.start_link(fn -> [] end)
    {:ok, mode} = Agent.start_link(fn -> :normal end)

    {:ok, listener} =
      Bandit.start_link(
        plug: {NativeFixture.Endpoint, requests: requests, mode: mode},
        ip: {127, 0, 0, 1},
        port: 0,
        startup_log: false
      )

    {:ok, {_, port}} = ThousandIsland.listener_info(listener)
    url = "http://127.0.0.1:#{port}"

    try do
      scanner_checks(tools, port)
      foray_checks(tools, url, requests)
      validation_cancellation = validation_failures(tools, url, mode, requests)
      timings = rate_checks(tools, url, requests)
      cancellation = cancellation_checks(tools, url, requests)
      Supervisor.stop(listener)
      assert eventually(fn -> reaped?() end)
      assert Enum.all?(wordlists(), &(not File.exists?(&1)))

      Integration.Assertions.finish(%{
        versions: %{rustscan: "2.4.1", nmap: "7.99", ffuf: "2.2.0", ffuf_reported: "2.1.0"},
        checks: [
          "rustscan_to_nmap",
          "open_closed_ports",
          "scope_denial",
          "real_ffuf",
          "persisted_exact_replay",
          "multi_keyword",
          "binary_body",
          "no_match",
          "response_receipt_refutation",
          "request_timeout_inconclusive",
          "job_deadline_inconclusive",
          "slow_consumer",
          "aggregate_rate",
          "consumer_death",
          "validation_caller_death",
          "child_reaping",
          "wordlist_cleanup",
          "audit_cleanup"
        ],
        rate: timings,
        cancellation_ms: cancellation,
        validation_cancellation_ms: validation_cancellation,
        child_count: length(pids())
      })
    after
      if Process.alive?(listener), do: Supervisor.stop(listener)
      Agent.stop(requests)
      Agent.stop(mode)
    end
  end

  defp validation_failures(tools, url, mode, requests) do
    plan =
      scan(tools, url, ["switch"])
      |> Foray.engine(Foray.Fuzz.Ffuf,
        executable: tools["ffuf"],
        runner: NativeFixture.Runner,
        request_timeout: 1
      )

    assert [finding] = plan |> Foray.stream() |> Enum.to_list()
    Agent.update(mode, fn _ -> :missing end)
    assert %{verdict: :refuted} = Foray.validate(finding, plan)
    Agent.update(mode, fn _ -> :silent end)
    assert %{verdict: :inconclusive, findings: []} = Foray.validate(finding, plan)

    deadline =
      plan
      |> Foray.rate(max_time: 1)
      |> Foray.engine(Foray.Fuzz.Ffuf,
        executable: tools["ffuf"],
        runner: NativeFixture.Runner,
        request_timeout: 3
      )

    assert %{verdict: :inconclusive, findings: []} = Foray.validate(finding, deadline)
    Agent.update(requests, fn _ -> [] end)
    validator = Task.async(fn -> Foray.validate(finding, plan) end)
    assert eventually(fn -> Enum.any?(Agent.get(requests, & &1), &(&1.path == "/switch")) end)
    started = System.monotonic_time(:millisecond)
    Task.shutdown(validator, :brutal_kill)
    assert eventually(fn -> reaped?() and Enum.all?(wordlists(), &(not File.exists?(&1))) end)
    elapsed = System.monotonic_time(:millisecond) - started
    assert elapsed < 5000
    elapsed
  after
    Agent.update(mode, fn _ -> :normal end)
  end

  defp scanner_checks(tools, port) do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, {_, closed}} = :inet.sockname(socket)
    :ok = :gen_tcp.close(socket)
    scope = Portico.Scope.Allowlist.new!(["127.0.0.1/32"])

    scan =
      Portico.scan("127.0.0.1", scope: scope)
      |> Portico.discover(
        ports: [port, closed],
        executable: tools["rustscan"],
        socket_timeout: 300,
        batch_size: 2
      )
      |> Portico.enrich(
        executable: tools["nmap"],
        scan_type: :connect,
        service_detection: false,
        resolve_dns: :never,
        timeout: 5000
      )

    assert [host] = scan |> Portico.stream() |> Enum.to_list()
    assert Enum.any?(host.ports, &(&1.number == port and &1.state == "open"))
    refute Enum.any?(host.ports, &(&1.number == closed and &1.state == "open"))

    assert {:ok, [closed_host]} =
             Portico.Enrichment.Nmap.enrich(
               [%Portico.Discovery.Result{ip: "127.0.0.1", ports: [closed]}],
               executable: tools["nmap"],
               scan_type: :connect,
               service_detection: false,
               resolve_dns: :never
             )

    assert Enum.any?(closed_host.ports, &(&1.number == closed and &1.state == "closed"))
    [finding | _] = Portico.Finding.from_host(host)

    binding =
      Binding.new!(Portico.Validator, "portico.endpoint-reachable.v1",
        resolver: fn _, _ -> {:ok, finding} end,
        validator_options: [
          scope: scope,
          engine_options: [
            executable: tools["nmap"],
            scan_type: :connect,
            service_detection: false,
            resolve_dns: :never
          ]
        ]
      )

    assert {:ok, %{verdict: :confirmed}} =
             Binding.invoke(binding, Wire.subject_reference(finding))

    assert_raise Core.Scope.Error, fn ->
      Binding.invoke(
        %{binding | validator_options: [scope: Core.Scope.DenyAll]},
        Wire.subject_reference(finding)
      )
    end
  end

  defp scan(tools, url, values) do
    Foray.target(url, scope: Foray.Scope.Allowlist.new!([url <> "/"]))
    |> Foray.fuzz_path(wordlist: seeds(values))
    |> Foray.match(codes: [200])
    |> Foray.rate(requests_per_second: 100, threads: 2, max_jobs: 1, max_time: 20)
    |> Foray.engine(Foray.Fuzz.Ffuf,
      executable: tools["ffuf"],
      runner: NativeFixture.Runner,
      request_timeout: 2,
      exit_timeout: 500
    )
  end

  defp foray_checks(tools, url, requests) do
    scan = scan(tools, url, ["admin", "missing"])
    assert [finding] = scan |> Foray.stream() |> Enum.to_list()
    assert finding.locus.status == 200
    assert finding.seed.value == "admin"
    File.write!("proofs/foray-finding.json", Foray.Result.encode!(finding))
    assert {:ok, restored} = "proofs/foray-finding.json" |> File.read!() |> Foray.Result.decode()

    binding =
      Binding.new!(Foray.Validator, "foray.http-match-reproduces.v1",
        resolver: fn _, _ -> {:ok, restored} end,
        validator_options: [scan: scan]
      )

    assert {:ok, %{verdict: :confirmed} = replay} =
             Binding.invoke(binding, Wire.subject_reference(restored))

    File.write!("proofs/foray-replay.json", replay |> Wire.result() |> Wire.encode!())

    assert [] = scan(tools, url, ["missing"]) |> Foray.stream() |> Enum.to_list()

    multi =
      Foray.target(url, scope: Foray.Scope.Allowlist.new!([url <> "/"]))
      |> Foray.fuzz_param("q", wordlist: seeds(["one", "two"]), keyword: "QUERY")
      |> Foray.fuzz_header("x-fixture", wordlist: seeds(["left", "right"]), keyword: "HEADER")
      |> Foray.rate(requests_per_second: 100, threads: 2, max_jobs: 1, max_time: 20)
      |> Foray.engine(Foray.Fuzz.Ffuf, executable: tools["ffuf"], runner: NativeFixture.Runner)

    matches = multi |> Foray.stream() |> Enum.to_list()
    assert length(matches) == 4
    assert length(Enum.uniq_by(matches, & &1.id)) == 4
    assert %{verdict: :confirmed} = Foray.validate(hd(matches), multi)

    payload = <<255, 0, ?A>>

    body =
      Foray.target(url, scope: Foray.Scope.Allowlist.new!([url <> "/"]), method: "POST")
      |> Foray.fuzz_body("FUZZ", wordlist: seeds([payload]))
      |> Foray.engine(Foray.Fuzz.Ffuf, executable: tools["ffuf"], runner: NativeFixture.Runner)

    assert [binary_finding] = body |> Foray.stream() |> Enum.to_list()
    assert binary_finding.seed.value == payload
    assert Enum.any?(Agent.get(requests, & &1), &(&1.body == payload))

    matches =
      scan(tools, url, Enum.map(1..80, &"flood-#{&1}"))
      |> Foray.stream()
      |> Stream.each(fn _ -> Process.sleep(5) end)
      |> Enum.to_list()

    assert length(matches) == 80
    assert length(Enum.uniq_by(matches, & &1.id)) == 80
  end

  defp rate_checks(tools, url, requests) do
    Agent.update(requests, fn _ -> [] end)

    scan =
      Foray.target([url <> "/first", url <> "/second"],
        scope: Foray.Scope.Allowlist.new!([url <> "/"])
      )
      |> Foray.fuzz_param("q", wordlist: seeds(Enum.map(1..10, &to_string/1)))
      |> Foray.rate(requests_per_second: 10, max_jobs: 2, threads: 2, max_time: 20)
      |> Foray.engine(Foray.Fuzz.Ffuf, executable: tools["ffuf"], runner: NativeFixture.Runner)

    assert 20 == scan |> Foray.stream() |> Enum.count()
    times = Agent.get(requests, & &1) |> Enum.map(& &1.at) |> Enum.sort()
    assert length(times) == 20
    elapsed = List.last(times) - hd(times)

    peak =
      Enum.map(times, fn start -> Enum.count(times, &(&1 >= start and &1 < start + 1000)) end)
      |> Enum.max()

    assert elapsed >= 1500
    assert peak <= 12

    %{
      requests: 20,
      configured_per_second: 10,
      observed_peak_one_second: peak,
      first_to_last_ms: elapsed,
      burst_tolerance: 2
    }
  end

  defp cancellation_checks(tools, url, requests) do
    Agent.update(requests, fn _ -> [] end)

    stream =
      scan(tools, url, ["silent"])
      |> Foray.engine(Foray.Fuzz.Ffuf,
        executable: tools["ffuf"],
        runner: NativeFixture.Runner,
        request_timeout: 25,
        exit_timeout: 500
      )
      |> Foray.stream()

    consumer = Task.async(fn -> Enum.to_list(stream) end)
    assert eventually(fn -> Enum.any?(Agent.get(requests, & &1), &(&1.path == "/silent")) end)
    started = System.monotonic_time(:millisecond)
    Task.shutdown(consumer, :brutal_kill)
    assert eventually(&reaped?/0)
    elapsed = System.monotonic_time(:millisecond) - started
    assert elapsed < 5000
    elapsed
  end

  defp observed(name, executable) do
    path = Path.expand("observed/#{name}")
    pid_file = Path.expand("observed/pids")
    words_file = Path.expand("observed/wordlists")

    File.write!(path, """
    #!/bin/sh
    printf '%s\\n' "$$" >> #{quote_shell(pid_file)}
    previous=''
    for arg in "$@"; do
      if [ "$previous" = '-w' ] || [ "$previous" = '-audit-log' ]; then printf '%s\\n' "$arg" >> #{quote_shell(words_file)}; fi
      previous="$arg"
    done
    exec #{quote_shell(executable)} "$@"
    """)

    File.chmod!(path, 0o700)
    path
  end

  defp quote_shell(value), do: "'" <> String.replace(value, "'", "'\\''") <> "'"

  defp seeds(values),
    do:
      Enum.with_index(values, fn value, index ->
        %Core.Seed{id: "native-#{index}", value: value, provenance: :wordlist}
      end)

  defp pids, do: "observed/pids" |> File.read!() |> String.split("\n", trim: true)

  defp wordlists,
    do:
      "observed/wordlists"
      |> File.read!()
      |> String.split("\n", trim: true)
      |> Enum.map(&(&1 |> String.split(":") |> hd()))

  defp reaped?,
    do:
      Enum.all?(pids(), fn pid ->
        elem(System.cmd("kill", ["-0", pid], stderr_to_stdout: true), 1) != 0
      end)

  defp eventually(fun, attempts \\ 150)
  defp eventually(_fun, 0), do: false

  defp eventually(fun, attempts) do
    if fun.(),
      do: true,
      else:
        (
          Process.sleep(20)
          eventually(fun, attempts - 1)
        )
  end
end

Integration.Native.run()
