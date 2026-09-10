# Havoc oracle semantics

The oracle is Havoc's central product surface and Rampart's validation trust
root. An oracle should encode a stated security invariant or a narrow signal—not
claim more than the observation can prove. `Havoc.validate/3` changes the
execution mode from search to one exact payload; it never upgrades an oracle's
confidence or semantics merely because a consumer requested confirmation.

`Havoc.Oracle.evaluate/4` retains three disjoint outcomes for every declared
oracle: passed, skipped, and violated. Search properties may continue after a
skip, but exact validation does **not** interpret missing evidence as safety. A
concrete validation is refuted only when every configured oracle actually
passes; one or more skips produce `:inconclusive`. Target/oracle failures are
also inconclusive and cannot produce a security finding unless the separately
declared `:no_crash` target invariant is what failed.

## Built-ins

### `:no_crash`

Passes when the property target returns normally. Havoc catches errors, throws,
and catchable exits raised by the target and reports a high-confidence `:crash`
finding. Untrappable process termination remains untrappable.

A failure in an oracle implementation is not a target crash. Havoc re-raises it
as a test error and does not persist a finding.

### `:no_500`

Rejects integer statuses in `500..599` by default. It accepts maps and
struct-like observations with `:status` or `:status_code` (and equivalent string
keys), including `Plug.Conn` without requiring Plug as a dependency.

A missing status is skipped by default. Set `missing: :fail` when the target
contract guarantees a status-bearing result and absence itself is unsafe.

A 500 is a reliability/security invariant violation; it does not identify the
root vulnerability.

### `:no_reflection`

Rejects exact, verbatim payload reflection. By default it checks only known
`text/html` and `application/xhtml+xml` responses and skips observations with no
content type. Configure `content_types: :any` or
`unknown_content_type: :check` only when the property contract warrants it.

Raw reflection is intentionally emitted with low confidence. Reflection can be
legitimate and is not a confirmed XSS vulnerability without analyzing output
context, encoding, and executable browser behavior. Use this oracle when the
application's invariant is specifically “attacker input must not be returned
verbatim,” or provide a context-aware custom oracle.

### `:no_injection_signal`

Looks for a small set of specific database disclosures such as `ORA-12345`,
`SQLSTATE[...]`, vendor-driver names, and characteristic SQL syntax errors. It
does not flag generic words such as “SQL” or “database.” Custom patterns may be
supplied as a non-empty list of `Regex` values.

A match is a medium-confidence information-disclosure/injection signal. It does
not by itself prove control of query execution. Confirmation requires a
separate invariant or differential test.

### `:no_sensitive_leak`

Looks for narrow stack-trace and exception-detail patterns in a body. It is
separate from injection signals because improper error handling is independently
triageable.

### `:terminal_safety`

Checks a captured terminal byte stream supplied directly or under
`:terminal_output`/`:output`. It rejects C0/DEL/C1 controls and escape sequences
that can alter terminal state. Newline and tab are allowed by default, as are
ordinary ANSI SGR color/style sequences; those allowances are configurable.
OSC, cursor movement, non-SGR CSI, bare escape, carriage return, bell, and
invalid UTF-8 remain violations.

This oracle proves that the bytes observed at the caller-designated terminal
boundary retained attacker-capable controls. It does not prove where the text
originated or that a particular terminal emulator performed a harmful action.
Use a negative fixed control and retain the exact output-producing fixture.

### `:canonical_encoding`

Consumes `%Havoc.Observation.Codec{}` values. Rejected inputs pass. Accepted
inputs pass only when the original input is exactly equal to the canonical
re-encoding of its decoded identity. An accepted alias produces a high-
confidence `:alternate_encoding` finding. The observation input must equal the
concrete payload being validated; a mismatch is a broken harness and therefore
inconclusive.

The caller owns the decoder and encoder fixture. For stronger codec validation,
combine this round-trip contract with generated collision pairs and an
independently specified valid-input grammar.

### `:quoted_parameter_integrity`

Consumes `%Havoc.Observation.HTTPParameter{}` built with
`HTTPParameter.authentication/4`. The bounded parser retains ordered duplicate
authentication parameters and implements HTTP token/quoted-string escaping
without depending on Plug. The oracle requires the designated parameter to
occur exactly once, use quoted-string form by default, decode to the independently
expected value, and match an optional expected authentication scheme. Malformed
output is a violation because the fixture observed an emitted header. Exceeding
the parser's header/parameter limits is skipped and therefore inconclusive,
rather than mislabeled as malformed output; a payload/observation mismatch is a
broken harness.

This proves parameter-boundary integrity for the one observed response. It does
not establish that the source value is attacker controlled or that every proxy,
client, and downstream parser interprets unrelated HTTP grammar identically.
The fixture should exercise a real response boundary and retain a fixed escaped
control.

### `:cache_partition_noninterference`

Consumes `%Havoc.Observation.Cache{}` from a two-partition scenario. The caller
must make uncached control requests for each partition and separately record the
value served to the second request through the shared-cache boundary. The oracle
confirms only when the direct values differ, both requests have the same cache
key, the second request is a cache hit, and its value is exactly the first
partition's value. A correct second value passes. No differing direct control,
or an unrelated corrupted value, is inconclusive rather than overclaimed.

Cache key calculation, cache-control/Vary semantics, tenant selection, response
projection, and the cache implementation remain fixture-owned. This contract
proves one concrete cross-partition replay, not universal cache poisoning.

### `:field_policy_noninterference`

Consumes `%Havoc.Observation.FieldPolicy{}`. A privileged actor must materially
observe every protected field on every declared path, establishing that the
field and operation are live. The paired restricted actor must observe each as
`:hidden`; any `{:visible, value}` is a high-confidence field-policy bypass for
the caller's independently declared policy contract. Missing privileged controls
or incomplete path observations are skipped, making exact validation
inconclusive.

Actor identity, protected-field selection, path equivalence, and adapters from
framework-specific return values to `hidden/0` or `visible/1` remain fixture-
owned. For Ash, exercise both ordinary record reads and alternate aggregate/tool
paths and derive the restricted expectation from the test policy, not from the
implementation under test.

### Differential invariants

`Havoc.Oracle.differential/3` consumes a
`%Havoc.Observation.Differential{control: ..., treatment: ...}` and invokes a
caller-supplied independent predicate over both observations and the payload.
It is a normalization primitive for actor, tenant, route, policy, and cache
noninterference checks—not an automatic comparison of arbitrary responses.
The caller must name the category and define which differences are forbidden.

### Bounded external state

`Havoc.Oracle.bounded_state_growth/1` consumes a
`%Havoc.Observation.State{before: ..., after: ..., settled: ...}`. It can bound
immediate cardinality growth and optionally require post-cleanup reclamation
within a tolerance. If reclamation is required but no settled measurement is
provided, exact validation is inconclusive rather than refuted.

Counters, cleanup/expiry advancement, quiescence, and the unit being measured
remain fixture-owned. This contract does not infer denial-of-service impact from
one count; it proves only the declared finite growth/retention budget.

### Authorization invariants

There is deliberately no automatic bare `:authz_invariant`. Authorization must
be checked against an independent expectation rather than asking the same code
under test whether access was allowed:

```elixir
oracle =
  Havoc.Oracle.authz_invariant(fn response, _case ->
    response.status in [401, 403] and
      response.protected_state_after == response.protected_state_before and
      response.privileged_side_effects == []
  end)
```

A status alone is not a complete authorization oracle. Strong properties also
verify no protected data was disclosed, no state changed, and no privileged
side effect occurred. Actor/resource/action matrices should derive expected
denials from test fixtures or an independent policy table.

## Deliberate v1 omissions

Havoc does not ship a generic `:no_timing_signal` oracle in v1. A defensible
timing test needs paired control/treatment samples, repeated measurements,
noise handling, and a caller-defined effect threshold; judging one response
duration would produce misleading findings. Those pieces can be assembled as a
custom oracle now and may graduate after validation against real timing leaks.

Likewise, Havoc does not claim that a reflected marker is executable XSS or that
a database error proves SQL injection. Confirmation belongs in a
context-specific or differential property.

## Custom oracles

```elixir
oracle =
  Havoc.Oracle.custom(
    :no_test_secret,
    fn response, _payload ->
      if String.contains?(response.body, "test-secret"),
        do: {:error, "response disclosed the test secret"},
        else: :ok
    end,
    category: :sensitive_leak,
    confidence: :high
  )
```

A checker returns one of:

- `:ok` or `true` to pass;
- `:skip` when the observation lacks what this oracle needs (inconclusive during
  exact validation);
- `false` for the generic predicate-failed evidence;
- `{:error, evidence}`; or
- `{:error, evidence, details}`.

Invalid returns and raised exceptions are ordinary test errors, not security
findings. In a `Havoc.validate/3` action they produce `:inconclusive`; in an
ExUnit property they remain test failures. Neither path may emit a confirmed
finding.

## Composition

Every declared oracle runs for an observation and violations retain declaration
order. A single shrunk payload can therefore emit multiple independently
triageable Core findings and counterexample seeds.

```elixir
Havoc.Oracle.compose([
  Havoc.Oracle.no_500(),
  Havoc.Oracle.no_reflection(content_types: :any),
  Havoc.Oracle.no_sensitive_leak()
])
```
