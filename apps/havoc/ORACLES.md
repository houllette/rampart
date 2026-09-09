# Havoc oracle semantics

The oracle is Havoc's central product surface and Rampart's validation trust
root. An oracle should encode a stated security invariant or a narrow signal—not
claim more than the observation can prove. `Havoc.validate/3` changes the
execution mode from search to one exact payload; it never upgrades an oracle's
confidence or semantics merely because a consumer requested confirmation.

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

- `:ok`, `:skip`, or `true` to pass;
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
