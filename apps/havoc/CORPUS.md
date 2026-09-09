# Havoc corpus

The corpus turns a transient property failure into a durable regression by
persisting the concrete shrunk input. It never relies only on StreamData's
random seed, because a seed no longer reproduces the same input after a
generator changes.

## Location and modes

The default path is `test/havoc/corpus.json`. Override it with:

1. a `path:`/`corpus_path:` option;
2. `HAVOC_CORPUS_PATH`; or
3. `config :havoc, corpus_path: "..."`.

Properties replay matching values before random generation. `mix havoc.replay`
sets `HAVOC_MODE=corpus_only` and runs ExUnit without the random phase.

Stable property IDs default to `ModuleName:property name`. Set `property_id:`
explicitly before renaming a test if long-term continuity matters.

## Version 1 format

The file is one JSON document:

```json
{
  "schema_version": 1,
  "seeds": [
    {
      "id": "havoc:...",
      "classes": ["no_500", "crash"],
      "provenance": "counterexample",
      "origin": {"source": "havoc", "finding_id": "havoc:..."},
      "value": {
        "encoding": "erlang-term-v1",
        "data": "g3Q...",
        "sha256": "..."
      },
      "meta": {
        "encoding": "erlang-term-v1",
        "data": "g3Q...",
        "sha256": "..."
      }
    }
  ]
}
```

Seed IDs sort deterministically. Writes take a per-path global lock, update by
ID, write a same-directory temporary file, set mode `0600`, and atomically
rename it over the old document. Parallel ExUnit properties therefore do not
silently overwrite one another inside one BEAM cluster.

## Exact terms and safety

Counterexamples may be binaries, tuples, maps, or application structs, so JSON
alone cannot preserve them exactly. Values and metadata use uncompressed Erlang
external-term encoding inside the versioned JSON envelope. Each term:

- is capped at 1 MiB before encode and after decode;
- carries a SHA-256 integrity digest;
- is decoded with `binary_to_term(..., [:safe])`; and
- cannot create atoms that do not already exist in the running VM.

The entire corpus is capped at 16 MiB. No compressed ETF is accepted, avoiding
a decompression amplification path.

These checks do not turn the corpus into a safe untrusted interchange parser.
Treat corpus files like test fixtures or source code: review changes and never
load a file supplied by an untrusted party. Use Core seeds with JSON-friendly
binary values for cross-service exchange.

## Import and export

Bind suite seeds to a property:

```elixir
{:ok, count} =
  Havoc.Corpus.import(seeds,
    property_id: "MyApp.SearchSecurityTest:search resists injection"
  )
```

Export payloads for Foray or another consumer:

```elixir
seeds =
  payloads
  |> Havoc.Corpus.export(classes: [:xss], provenance: :generated)
```

`Havoc.promote/3` preserves a source finding's `{source, finding_id}` as the
seed origin. Havoc itself never depends on Portico or Foray.

## Lifecycle

Passing a previously failing concrete input does not delete it. The corpus is a
regression suite, not a queue: keeping fixed counterexamples catches future
regressions. Remove a case only through an intentional, reviewed corpus change.
