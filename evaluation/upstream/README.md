# Complete pinned upstream package evaluation

`mix rampart.upstream` fetches complete, content-addressed upstream repositories,
compiles each revision as an actual dependency of a fresh external Mix project,
and executes the same host-owned Havoc contract against the pre-fix and fixed
package code. A mutable branch or release label is never accepted: both commit
and Git tree IDs must match `cases.json`.

The initial gate covers two Mint 1.9.3 boundaries:

- CVE-2026-82728: incomplete HTTP/1 response lines must remain within the
  configured byte budget; the check executes `Mint.HTTP1.connect/request/stream`
  over an owned loopback connection.
- CVE-2026-82729: chunk-size parsing must reject more than sixteen hexadecimal
  digits; the check executes the package's hidden `chunk_size/1` function in the
  `Mint.HTTP1.Parse` module.

Both checks include an exact-boundary positive control. The vulnerable revision
must return a Havoc `confirmed` verdict, the fixed revision must return
`refuted`, and both must receive the same original input seed ID and
fingerprint. (A confirmed Havoc result may derive its proof seed ID from the
finding.) Reports retain upstream commit/tree/license identities, the relevant
local source-snapshot hash (including uncommitted files), actual loaded BEAM
paths, package versions, wire-projected results, and bounded logs.

```sh
mix rampart.upstream
mix rampart.upstream --output tmp/upstream.json --keep-workspace
```

This is a networked, slow integration gate rather than part of `mix precommit`.
It executes complete package code, but it is still a reviewed, patch-informed
regression—not blind discovery and not evidence about every Mint state or every
Erlang/Elixir package. It currently fetches public GitHub and Hex content and
must run inside the disposable sandbox described in `evaluation/isolation/`
when the source is not already reviewed and pinned.
