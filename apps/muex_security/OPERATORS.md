# Security mutation operators

Security mutations should answer a concrete question: “would the test suite
notice if this defensive control stopped working?” The pack therefore uses
narrow syntax/name allowlists instead of mutating every predicate, string, or
function call.

## `security_decision`

Forces module-qualified allow-shaped predicates such as `Policy.authorized?`,
`Token.valid_signature?`, and `CSRF.csrf_valid?` (when the function name is in the
operator allowlist) to `true`. Forces module-qualified deny-shaped predicates
such as `Token.revoked?`, `expired?`, `rate_limited?`, and `blocked?` to `false`.

It intentionally does not mutate generic `valid?`, `ok?`, or `enabled?` calls;
those names create too many non-security mutants. Teams can wrap controls in a
semantically named predicate or contribute a reviewed extension. Calls must be
module-qualified because Muex 0.9's traversal does not expose parent context: a
local call AST is indistinguishable from a function-definition head, and
mutating the latter produces invalid `def true` mutants.

## `sanitizer_bypass`

Replaces module-qualified calls with narrowly recognized names
(`HTML.sanitize_html`, `Phoenix.HTML.html_escape`, `Redactor.redact`, and related
names) by their raw first argument. This
models a missing output-encoding, sanitization, or secret-redaction layer while
usually preserving the caller's expected value shape.

Generic `encode`, `escape`, and arbitrary one-argument functions are excluded.

## `secure_compare`

Replaces `Plug.Crypto.secure_compare/2` and `:crypto.hash_equals/2` calls with
ordinary `==`. A surviving mutant shows that
tests assert equality behavior but do not exercise the constant-time control.
It does not claim to measure timing directly.

## `security_header`

Replaces a recognized static `put_resp_header/3` write with its input connection,
removing CSP, HSTS, clickjacking, MIME-sniffing, referrer, permissions, and
cross-origin policy headers. Dynamic header names are skipped because their
security meaning cannot be established from local AST.

## `transport_security`

Changes `verify: :verify_peer` to `verify: :verify_none` and
`check_hostname: true` to `false`. It only targets explicit keyword tuples; it
does not guess defaults for an HTTP/TLS library.

## Expected surviving mutants

A surviving security mutant is a prompt to inspect tests, not automatic proof
of a production vulnerability. Equivalent behavior can be enforced at another
layer (reverse proxy headers, centralized policy plugs, TLS client defaults),
or a mutation may sit on an unreachable configuration branch. Use Muex's
coverage-guided mode and inspect the patch before treating a survivor as a
finding.
