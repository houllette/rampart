Code.require_file("../assertions.exs", __DIR__)
import ExUnit.Assertions
Integration.Assertions.isolated!()
seed = %Core.Seed{id: "consumer", value: "payload", provenance: :generated}

assert %{verdict: :confirmed} =
         Havoc.validate(seed, fn _ -> %{status: 500} end,
           oracles: [:no_500],
           corpus_path: "corpus.json"
         )

assert [saved] = Havoc.Corpus.load(path: "corpus.json")
assert saved.value == seed.value

assert %{verdict: :refuted} =
         Havoc.validate(saved, fn _ -> %{status: 200} end, oracles: [:no_500], persist: false)

Integration.Assertions.finish(%{
  checks: ["package_isolation", "confirmed", "persisted_replay", "refuted"]
})
