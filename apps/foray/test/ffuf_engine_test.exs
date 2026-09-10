defmodule Foray.FfufEngineTest do
  use ExUnit.Case, async: true

  alias Core.Seed
  alias Foray.Fuzz.Ffuf
  alias Foray.JobBuilder
  alias Foray.Scope.Allowlist

  @fixture Path.expand("fixtures/ffuf_v2_2.ndjson", __DIR__)

  test "indexed provenance preserves first seed and keyword precedence" do
    first = %Seed{id: "first", value: "same", provenance: :wordlist}
    duplicate = %{first | id: "duplicate"}
    later = %{first | id: "later-keyword"}

    wordlists = [
      %Foray.Wordlist{ref: "one", keyword: "A", source: {:seeds, [first, duplicate]}},
      %Foray.Wordlist{ref: "two", keyword: "B", source: {:seeds, [later]}}
    ]

    index = Foray.Wordlist.index(wordlists)
    assert Foray.Wordlist.indexed_seed(index, %{"A" => "same", "B" => "same"}) == first
    assert Foray.Wordlist.indexed_seed(index, %{"A" => "missing", "B" => "same"}) == later
    assert Foray.Wordlist.indexed_seed(index, %{"A" => "missing"}) == nil
  end

  test "real projected identities join an exact replay and legacy identities require re-observation" do
    scan =
      Foray.target("https://app.example", scope: Allowlist.new!(["https://app.example/"]))
      |> Foray.fuzz_path(wordlist: "paths.txt")
      |> Foray.engine(Ffuf,
        executable: "sh",
        runner: Foray.TestChunkRunner,
        runner_options: [observer: self(), chunks: [first_match_line()]]
      )

    [job] = JobBuilder.build(scan)
    [candidate] = Ffuf.stream(job, scan.engine.opts) |> Enum.to_list()
    assert candidate.locus.identity_version == 3
    assert {:ok, restored} = candidate |> Foray.Result.encode!() |> Foray.Result.decode()
    assert restored.locus.identity_version == 3
    assert %{verdict: :confirmed} = Foray.validate(restored, scan)
    assert %{verdict: :confirmed, findings: [replayed]} = Foray.validate(candidate, scan)
    assert replayed.id == candidate.id

    for version <- [nil, 1, 2] do
      legacy = put_in(candidate.locus.identity_version, version)

      assert %{
               verdict: :inconclusive,
               evidence: %{facts: %{reason: :unsupported_identity_version}}
             } =
               Foray.validate(legacy, scan)
    end
  end

  defp first_match_line,
    do: @fixture |> File.read!() |> String.split("\n", parts: 2) |> hd() |> Kernel.<>("\n")

  test "rejects ffuf versions below the pinned security floor" do
    assert {:error, {:unsupported_ffuf_version, "2.1.0", "2.2.0"}} =
             Ffuf.validate_runtime(executable: "sh", runner: Foray.TestOldRunner)

    assert :ok = Ffuf.validate_runtime(executable: "sh", runner: Foray.TestChunkRunner)
  end

  test "builds typed ffuf arguments with a conservative share of aggregate rate" do
    scope = Allowlist.new!(["https://app.example/"])

    scan =
      Foray.target(["https://app.example", "https://api.app.example"], scope: scope)
      |> Foray.fuzz_param("q", wordlist: "payloads.txt", class: :sqli)
      |> Foray.match(codes: [200, 301..303], regex: ~r/SQL syntax/, mode: :and)
      |> Foray.filter(size: [0, 42], words: 3)
      |> Foray.rate(requests_per_second: 50, threads: 40, max_jobs: 2, max_time: 60)

    [job | _rest] = JobBuilder.build(scan)
    command = Ffuf.command(job, [])

    assert job.request_rate == 25
    assert flag_value(command, "-u") == "https://app.example/?q=FUZZ"
    assert flag_value(command, "-w") == "payloads.txt:FUZZ"
    assert flag_value(command, "-rate") == "25"
    assert flag_value(command, "-t") == "40"
    assert flag_value(command, "-mc") == "200,301-303"
    assert flag_value(command, "-mr") == "SQL syntax"
    assert flag_value(command, "-fs") == "0,42"
    assert flag_value(command, "-fw") == "3"
    assert flag_value(command, "-mmode") == "and"
    assert "-json" in command
    refute "-v" in command
  end

  test "materializes Core seeds lazily, preserves provenance, and removes the temporary corpus" do
    seed = %Seed{
      id: "admin-seed",
      value: "admin",
      classes: [:discovery],
      provenance: :counterexample
    }

    scan =
      Foray.target("https://app.example", scope: Allowlist.new!(["https://app.example/"]))
      |> Foray.fuzz_path(wordlist: [seed])

    [job] = JobBuilder.build(scan)
    chunks = [File.read!(@fixture) |> String.split("\n", parts: 2) |> hd() |> Kernel.<>("\n")]

    assert [finding] =
             Ffuf.stream(job,
               runner: Foray.TestChunkRunner,
               runner_options: [observer: self(), chunks: chunks]
             )
             |> Enum.to_list()

    assert finding.seed == seed
    assert finding.category == :exposed_path
    assert finding.locus.input == "admin"

    assert_receive {:command, command}
    corpus_arg = flag_value(command, "-w")
    corpus_path = String.replace_suffix(corpus_arg, ":FUZZ", "")
    refute File.exists?(corpus_path)
  end

  test "translates named positions into ffuf sniper templates" do
    scan =
      Foray.target("https://app.example")
      |> Foray.fuzz_param("q", wordlist: "payloads.txt")
      |> Foray.fuzz_header("X-Test", wordlist: "payloads.txt")
      |> Foray.mode(:sniper)

    [job] = JobBuilder.build(scan)
    command = Ffuf.command(job, [])

    assert flag_value(command, "-u") == "https://app.example/?q=§FUZZ§"
    assert flag_value(command, "-w") == "payloads.txt"
    assert Enum.chunk_every(command, 2, 1, :discard) |> Enum.member?(["-H", "X-Test: §FUZZ§"])
  end

  test "rejects ambiguous input commands and ffuf-managed redirects" do
    scan = Foray.target("https://app.example")

    assert_raise ArgumentError, ~r/reserves it as the keyword separator/, fn ->
      Foray.fuzz_path(scan, wordlist: {:input_command, "printf 'https://x'", 1})
    end

    assert_raise NimbleOptions.ValidationError, fn ->
      Foray.target("https://app.example", engine_options: [follow_redirects: true])
    end
  end

  test "rejects ffuf's reserved metadata keyword as a payload source" do
    [job] =
      Foray.target("https://app.example")
      |> Foray.fuzz_param("q", wordlist: "payloads.txt", keyword: "FFUFHASH")
      |> JobBuilder.build()

    assert_raise ArgumentError, ~r/FFUFHASH/, fn -> Ffuf.command(job, []) end
  end

  defp flag_value(command, flag) do
    command
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.find_value(fn
      [^flag, value] -> value
      _pair -> nil
    end)
  end
end
