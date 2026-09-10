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

text_seed = %{seed | value: "a" <> String.duplicate("\u0301", 4)}
length_oracle = Havoc.Oracle.bounded_length(unit: :bytes, max_length: 4)

assert %{verdict: :confirmed} =
         Havoc.validate(text_seed, &Havoc.Observation.Length.accepted(&1, &1),
           oracles: [length_oracle],
           persist: false
         )

assert %{verdict: :inconclusive} =
         Havoc.validate(text_seed, fn _ -> %{} end, oracles: [length_oracle], persist: false)

target = fn chunks ->
  Havoc.Observation.Incremental.capture(
    chunks,
    %{buffer: "", work: 0},
    fn chunk, state ->
      next = %{buffer: state.buffer <> chunk, work: state.work + byte_size(chunk)}

      if String.ends_with?(next.buffer, "\n"),
        do: {:accepted, %{next | buffer: ""}},
        else: {:incomplete, next}
    end,
    fn state -> %{retained_bytes: byte_size(state.buffer), work: state.work} end,
    work_unit: :bytes_processed
  )
end

partition_seed = %{seed | value: ["12345", "\n"]}

oracles = [
  Havoc.Oracle.incremental_buffer_budget(max_bytes: 4),
  Havoc.Oracle.incremental_work_budget(unit: :bytes_processed, max_work: 5)
]

assert %{verdict: :confirmed, findings: findings} =
         Havoc.validate(partition_seed, target,
           oracles: oracles,
           corpus_path: "resource-corpus.json"
         )

assert length(findings) == 2
assert [replay | _] = Havoc.Corpus.load(path: "resource-corpus.json")
assert replay.value === partition_seed.value
assert %{verdict: :confirmed} = Havoc.validate(replay, target, oracles: oracles, persist: false)

assert %{verdict: :refuted} =
         Havoc.validate(%{seed | value: ["1234", "\n"]}, target, oracles: oracles, persist: false)

for chunks <- Enum.take(Havoc.Gen.byte_partitions(<<255, 0, 1>>, max_chunks: 2), 10) do
  assert IO.iodata_to_binary(chunks) == <<255, 0, 1>>
  assert length(chunks) <= 2
end

for value <- Enum.take(Havoc.Gen.unicode_length(max_bytes: 8), 10) do
  assert byte_size(value) <= 8 and String.valid?(value)
end

Integration.Assertions.finish(%{
  checks: [
    "package_isolation",
    "confirmed",
    "persisted_replay",
    "refuted",
    "explicit_length",
    "missing_measurement",
    "incremental_buffer_and_work",
    "partition_replay",
    "resource_fixed_control",
    "bounded_generators"
  ]
})
