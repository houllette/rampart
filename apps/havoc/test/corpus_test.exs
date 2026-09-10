defmodule Havoc.CorpusTest do
  use ExUnit.Case, async: true

  alias Core.Seed

  setup context do
    path =
      Path.join(
        System.tmp_dir!(),
        "havoc-corpus-#{context.test}-#{System.unique_integer([:positive])}.json"
      )

    on_exit(fn -> File.rm_rf(path) end)
    %{path: path}
  end

  test "persists exact concrete terms in a versioned, deterministic corpus", %{path: path} do
    seed = %Seed{
      id: "seed:b",
      value: %{payload: <<0, 255>>, role: :outsider, path: {"users", 42}},
      classes: [:authz_bypass],
      provenance: :counterexample,
      origin: {:havoc, "finding:1"},
      meta: %{property_id: "Example:property", oracle: :authz_invariant}
    }

    assert :ok = Havoc.Corpus.put(seed, path: path)
    assert [^seed] = Havoc.Corpus.load(path: path)

    decoded = path |> File.read!() |> Jason.decode!()
    assert decoded["schema_version"] == 1
    assert [%{"value" => %{"encoding" => "erlang-term-v1"}}] = decoded["seeds"]
  end

  test "upserts by seed id and filters by property with stable ordering", %{path: path} do
    seed_b = seed("b", "property:two", "old")
    seed_a = seed("a", "property:one", "one")
    replacement = %{seed_b | value: "new"}

    assert :ok = Havoc.Corpus.put(seed_b, path: path)
    assert :ok = Havoc.Corpus.put(seed_a, path: path)
    assert :ok = Havoc.Corpus.put(replacement, path: path)

    assert Enum.map(Havoc.Corpus.load(path: path), & &1.id) == ["a", "b"]

    assert [%Seed{id: "b", value: "new"}] =
             Havoc.Corpus.load(property_id: "property:two", path: path)
  end

  test "imports suite seeds and deduplicates exact replay values", %{path: path} do
    first = seed("one", "property", "same")
    second = seed("two", "property", "same")
    third = seed("three", "property", "different")

    assert {:ok, 3} = Havoc.Corpus.import([first, second, third], path: path)

    assert ["different", "same"] =
             Havoc.Corpus.replay_values("property", path: path)
             |> Enum.sort()
  end

  test "serializes concurrent property writes without losing seeds", %{path: path} do
    1..20
    |> Task.async_stream(
      fn number ->
        Havoc.Corpus.put(seed(Integer.to_string(number), "property", number), path: path)
      end,
      max_concurrency: 10,
      ordered: false
    )
    |> Enum.each(fn result -> assert result == {:ok, :ok} end)

    assert Havoc.Corpus.load(path: path) |> Enum.map(& &1.value) |> Enum.sort() ==
             Enum.to_list(1..20)
  end

  test "rejects tampered term payloads instead of decoding them", %{path: path} do
    assert :ok = Havoc.Corpus.put(seed("one", "property", "payload"), path: path)

    document = path |> File.read!() |> Jason.decode!()
    [entry] = document["seeds"]
    corrupted = put_in(entry, ["value", "sha256"], String.duplicate("0", 64))
    File.write!(path, Jason.encode!(%{document | "seeds" => [corrupted]}))

    assert_raise Havoc.Corpus.Error, ~r/integrity/, fn ->
      Havoc.Corpus.load(path: path)
    end
  end

  test "uses deterministic fingerprints for equivalent map values" do
    first = Enum.into([{:a, 1}, {:b, 2}], %{})
    second = Enum.into([{:b, 2}, {:a, 1}], %{})

    assert Havoc.TermCodec.fingerprint(first) == Havoc.TermCodec.fingerprint(second)
  end

  test "rejects runtime-only values that cannot be replayed", %{path: path} do
    assert_raise ArgumentError, ~r/non-replayable/, fn ->
      Havoc.Corpus.put(seed("pid", "property", self()), path: path)
    end
  end

  test "rejects an oversized import without replacing the existing proof", %{path: path} do
    original = seed("original", "property", "proof")
    assert :ok = Havoc.Corpus.put(original, path: path)
    before = File.read!(path)
    payload = :binary.copy("a", 950_000)
    seeds = for number <- 1..14, do: seed("large-#{number}", "property", payload)

    assert_raise Havoc.Corpus.Error, ~r/corpus_too_large/, fn ->
      Havoc.Corpus.import(seeds, path: path)
    end

    assert File.read!(path) == before
    assert [^original] = Havoc.Corpus.load(path: path)
  end

  test "batch imports retain the last duplicate and merge existing IDs", %{path: path} do
    original = seed("original", "property", "proof")
    assert :ok = Havoc.Corpus.put(original, path: path)
    first = seed("duplicate", "property", "first")
    last = %{first | value: "last"}
    assert {:ok, 2} = Havoc.Corpus.import([first, last], path: path)
    assert [^last, ^original] = Havoc.Corpus.load(path: path)
  end

  defp seed(id, property_id, value) do
    %Seed{
      id: id,
      value: value,
      classes: [:sqli],
      provenance: :counterexample,
      origin: {:havoc, "finding"},
      meta: %{property_id: property_id, oracle: :no_500}
    }
  end
end
