# Rampart ↔ Lemieux integration direction

This note records an implementation-level review of
[`houllette/lemieux`](https://github.com/houllette/lemieux) at commit
`76bd70322daae8ce47f53ed3993ee8d07f2c8452` (reviewed 2026-09-09). It replaces the earlier assumption
that Lemieux was only a future generic agent loop.

Lemieux is already a library-first coding-agent harness with governed tool
execution, append-only transcripts, resumable sessions, content-addressed
artifacts, structured tool results, and host-owned policy hooks. Rampart should
fit those contracts deliberately, but **must not depend on Lemieux**. Rampart
provides deterministic security primitives; Lemieux remains one consumer and
owns model/tool iteration.

## Consequences for Rampart

### 1. Keep the dependency boundary

No Rampart package adds Lemieux as a dependency. `security_core` remains the
transport-neutral interchange package and Lemieux remains outside this
umbrella. An adapter may depend on both projects later, but it belongs at the
consumer boundary and must not become part of Core's runtime.

This preserves both projects' library-first rules:

- Rampart validators work from ordinary Elixir and CI without a model.
- Lemieux can change providers, prompts, or orchestration without changing a
  scanner, oracle, or sensor.
- Rampart can be consumed by another harness without emulating Lemieux.

### 2. Bind authority on the host; pass only inert references

Lemieux's `host_tools` are current capabilities. They are supplied by the host
for a session and are deliberately not restored from transcripts. This is the
right model for Rampart validation authority.

A model must never provide any of the following as tool arguments:

- a `Core.Scope` policy or an allow-all switch;
- a `Core.Runner` backend or scanner engine module;
- a Foray originating `%Foray.Scan{}`;
- a Havoc target function, oracle implementation, or corpus path; or
- arbitrary Portico/Foray engine options.

The host binds those values with `Core.Validation.Binding`. The model-facing
input is only:

```json
{
  "subject_type": "finding",
  "subject_id": "foray:..."
}
```

The binding resolves that identifier from a host-authorized repository and
calls the ordinary validator with host-owned options. Bindings contain
functions and policy state, are intentionally non-serializable, and must be
rebuilt after resume or fork. Unknown input fields are rejected rather than
ignored, preventing an argument rewrite from smuggling execution authority.

### 3. Use action-scoped descriptors and a small active catalog

Lemieux treats every visible tool schema as a permanent model-context cost, and
its policy engine reasons from a static `Lemieux.Tool.Descriptor`. Rampart
should therefore not expose every internal primitive or one enormous unsafe
catch-all tool.

The recommended adapter is one configured tool per **enabled validation
action**, with the host profile selecting only the small set relevant to the
current task. The current catalog contains five v1 actions, with IAST withheld:

| Action | Proof established | Initial agent availability |
| --- | --- | --- |
| `portico.endpoint-reachable.v1` | One endpoint is reachable during the probe | Host-authorized network profile |
| `foray.http-match-reproduces.v1` | The exact recorded HTTP match reproduces | Host-authorized network profile; identity v3 required |
| `havoc.security-property-reproduces.v1` | A concrete input violates the configured security oracle | Host-owned execution fixture and oracle |
| `sast.rule-matches-source.v1` | The selected rule still matches the supplied syntax | Trusted snapshot replay; reconnaissance of untrusted projects uses `RampartSAST.Isolated` |
| `iast.exact-marker-reaches-sink.v1` | An unchanged marker reaches a sink in one execution process | Withheld while research gates remain open |

The host should partition the catalog by workflow and effect class. Neither
static replay nor a reproduced HTTP match alone establishes a vulnerability.
Foray findings recorded before identity v3 require re-observation before replay.

Map `Core.Validation.Action` as follows:

| Rampart | Lemieux descriptor |
| --- | --- |
| versioned action `id` | canonical identity + contract version |
| `description` | model-facing tool description |
| `Core.Validation.Wire.input_schema/1` | input JSON Schema |
| `side_effects: :authorized_probe` | external effect, not read-only, policy approval |
| `side_effects: :test_execution` | write/test effect, not read-only |
| `side_effects: :none` | read-only syntactic action, subject to host snapshot policy |
| host-bound deadline | descriptor runtime timeout |
| validator implementation + action bytes | implementation digest input |
| action-scoped binding | exclusive by default; resource-keyed only when proved safe |

Portico and Foray make external network effects even when their monetary cost
is zero. Their descriptor may declare a substantiated maximum of `$0.00` for
API spend while retaining the external effect and approval requirement. Do not
mark them read-only. Havoc can persist a counterexample, so its validation tool
is not read-only either. This also keeps effectful Rampart tools out of
Lemieux's read-only delegated A2A sessions by default.

Descriptor timeouts must come from the bound execution configuration and remain
within the session's `tool_timeout_ms` maximum. At the reviewed revision, that
host maximum defaults to ten minutes; descriptor defaults may be lower. Set
both explicitly for the intended workload rather than relying on those defaults.

### 4. Keep verdicts distinct from tool failures

A completed Rampart action returning `:confirmed`, `:refuted`, or
`:inconclusive` is a successful tool invocation. In particular,
`:inconclusive` is domain evidence, not a Lemieux tool error.

Malformed references, missing current authority, scope denial, harness-level
cancellation/deadline expiry, and implementation crashes are tool failures.
Lemieux records those as model-readable durable outcomes. A validator may still
complete normally with `:inconclusive` after observing a target/probe timeout;
that is different from Lemieux terminating the tool task. An adapter must not
convert a crash into a confirmed finding or collapse a scope denial into
`:inconclusive`.

### 5. Project results; never serialize native structs wholesale

`%Core.Finding{}.raw`, `%Core.Seed{}.value`, validation request context, and
validator options can contain arbitrary structs, malformed binaries,
functions, or sensitive data. They do not belong in a transcript.

`Core.Validation.Wire` now provides the explicit bridge projection:

- versioned, string-keyed JSON objects;
- a deterministic SHA-256 over the projection;
- concise model-facing text;
- no native `raw` fields;
- no concrete seed value by default; and
- a digest/size marker instead of invalid JSON for malformed binary evidence.

An adapter can return:

```elixir
Lemieux.Tool.Result.new(Core.Validation.Wire.model_text(result),
  structured_content: Core.Validation.Wire.result(result),
  artifacts: artifact_references
)
```

Large traces, HTTP exchanges, scanner XML, corpus entries, and IAST path proof
should be persisted by a host-authorized artifact service. The tool result
carries only content-addressed references. Lemieux's artifact locator is a
reference, never access authority; the host still resolves it under current
scope.

Budget the complete `Lemieux.Tool.Result` envelope, including model text and
artifact references. The reviewed `Result.limit/2` replaces oversized structured
content with a truncation marker and clears artifacts/metadata. The adapter must
externalize large evidence before reaching that fallback, leaving enough room
for the reference and verdict in the final envelope.

Including a seed value in the wire projection is an explicit host decision.
Exact replay remains available in the native result and the Rampart corpus,
even when the model sees only the seed ID and artifact reference.

### 6. Do not expose scan streams as unbounded model output

Rampart's native `Stream` APIs remain the right embedding interface, but a
Lemieux streaming tool is an iodata stream with an output budget—not a durable
per-item structured finding bus. A Lemieux adapter should run a bounded
observe/validate operation, return a capped structured summary, and externalize
the complete finding set as an artifact. It must not dump an unbounded Portico
or Foray stream into model context.

### 7. Correlate evidence instead of copying it

Lemieux sessions accept correlation IDs, harness context, and evidence artifact
references. A host should correlate a Rampart request/result ID with the
Lemieux session, call, and run-evidence manifest. It should not copy prompts,
tool arguments, raw traffic, or large proof bodies into multiple evidence
objects.

A future adapter should place the Rampart action ID, request ID, result ID,
result projection digest, and artifact IDs in Lemieux result metadata or the
run manifest's extension area. Rampart's durable corpus remains proof memory;
Lemieux's append-only transcript remains execution history.

## Important namespace boundary: discovery is not security validation

Lemieux also contains `Lemieux.Harness.Discovery.*` contracts for bounded
search over **harness assets**. Its candidates, development/validation
measurements, Pareto frontier, and
`Lemieux.Harness.Discovery.Confirmation.to_experiment/3` are not vulnerability
findings and are not aliases for `Core.Validation`.

The boundary is one-way and evidence-driven:

- a Rampart validation result may be an objective or safety observation when a
  host evaluates a harness candidate;
- harness discovery cannot activate code or grant scanner authority;
- a Pareto-frontier candidate is not a confirmed security finding; and
- Lemieux's independent experiment confirmation must never be pre-populated
  from exploratory Rampart results.

Keeping the terms separate prevents search quality from laundering a security
hypothesis—or generated harness code—into trusted proof.

## Experimental IAST sensor

RampartIAST remains unavailable to Lemieux while its research gates are open.
The reviewed Lemieux contracts sharpen the sensor's eventual external interface:

1. Persist full trace/path evidence as content-addressed artifacts; expose only
   bounded facts and references to the model.
2. Accept an inert `%Core.Hypothesis{}` identifier and resolve the current sink
   map, replay driver, trace policy, and environment on the host.
3. Advertise each sensor validation procedure as a versioned action with an
   explicit effect and timeout.
4. Treat trace setup failures, dropped events, ambiguous call-site provenance,
   and incomplete capture as `:inconclusive`, never `:confirmed`.
5. Record exact action/result/artifact digests so a Lemieux run can point to the
   proof without becoming the proof store.

These constraints reinforce—not relax—the north-star rule: Lemieux decides
what deterministic Rampart capability to call; Rampart alone decides what the
observations prove.

## Executable consumer handoff

Start with `mix rampart.integration --suite consumers`, then `--suite contracts`
and `--suite applications`. The [integration gate](evaluation/integration/README.md)
builds and consumes actual package archives in fresh projects and retains its
reports and replay artifacts. It exercises all three verdicts, scope denial,
malformed references, option smuggling, validator crashes, completed target
failures, cancellation, deadlines, rebuilt current authority, and oversized
evidence. Full Lemieux descriptor/result wrapping and transcript resume tests
belong in the separate security application.

[examples/bound_validation.exs](examples/bound_validation.exs) is a tested,
transport-neutral embedding example. The host starts a task supervisor, builds
the binding, then calls `RampartExample.BoundValidation.start/4` and `await/2`:

```elixir
{:ok, supervisor} = Task.Supervisor.start_link()
binding = Core.Validation.Binding.new!(Havoc.Validator,
  "havoc.security-property-reproduces.v1",
  resolver: host_seed_resolver,
  validator_options: [target: reviewed_target,
    property_options: [oracles: reviewed_oracles, corpus_path: host_corpus_path]])

task = RampartExample.BoundValidation.start(supervisor, binding, subject_reference,
  output_limit: 4096, artifact_directory: host_artifact_directory)
result = RampartExample.BoundValidation.await(task, 5000)
```

The example bounds its own projection, not a surrounding Lemieux envelope. It
is evaluation/example code, not a new Rampart harness or a ready-made Lemieux
adapter. A real host supplies artifact authorization, binding reconstruction,
descriptor policies, and final envelope budgeting. Neither repository adds the
other as a dependency.
