# Agent Guidelines

## Project overview

This repository is the Rampart Elixir security-tooling umbrella. The north star
is a deterministic BEAM-native IAST foundation spanning static, dynamic, and
interactive analysis; read `NORTH_STAR.md` before component briefs. Rampart is
not the human platform or Lemieux agent harness. Every primitive must remain
correct and useful without an LLM, and every analysis tool must expose a
specific proof/refutation action rather than only report candidates.

Each child under `apps/` is an independently versioned and publishable library.
`security_core` is the suite's dependency-free-inside-the-suite contract spine;
tools such as Portico depend on Core but never on sister tools. Cross-tool
orchestration and agent reasoning belong outside Core and outside individual
tools.

Portico orchestrates a backpressured RustScan-to-nmap pipeline and keeps its rich
native domain model. Foray orchestrates whole ffuf jobs and must never fan
individual payloads into BEAM tasks. Havoc runs in-process: it builds security
oracles, adversarial generators, durable regressions, and concrete validation
on StreamData rather than rebuilding property-based testing. All tools project
observations into Core findings only at the cross-tool boundary and advertise
versioned actions through `Core.Validation`/`Core.Validator`.

The experimental `rampart_iast` sensor is a gated research track. Its first
action proves only unchanged-marker reachability inside one traced execution
process. Do not treat value equality as taint tracking, OTP Cover as a sensor,
or a traced sink MFA as a unique call site. Keep context/sink maps pluggable;
cross-process taint and production safety require evidence before becoming
load-bearing. Sensor-owned source/sink/observation types do not belong in Core.

Lemieux is an external consumer, not an umbrella dependency; read
`LEMIEUX_INTEGRATION.md` before changing an agent-facing contract. Model-facing
inputs are inert subject references. Scope, scan plans, target functions,
resolvers, and artifact access stay in host-owned `Core.Validation.Binding`
values and are never restored from a transcript. Use `Core.Validation.Wire` for
transcript-safe JSON and enforce the adapter's configured output limit; never
serialize native `raw` fields or executable context. Treat all three validation
verdicts as completed domain results, and keep scope
denial, harness deadline/cancellation, and crashes as distinct tool failures. A
probe timeout captured by a completed validator may be inconclusive evidence.
Do not conflate Lemieux harness-candidate confirmation with vulnerability
validation.

## Commands

Everything below is bundled into one alias. **Run `mix precommit` when you
think you're done** — it runs the same checks CI runs, so a green `precommit`
means a green PR.

| Task | Command |
| --- | --- |
| Everything (run this before you're done) | `mix precommit` |
| Install deps | `mix deps.get` |
| Compile (warnings are errors in CI) | `mix compile --warnings-as-errors` |
| Run all tests | `mix test` |
| Run one test file | `mix test apps/APP/test/path/to/file_test.exs` |
| Run one test | `mix test apps/APP/test/path/to/file_test.exs:LINE` |
| Format | `mix format` |
| Lint | `mix credo --strict` |
| Compile-time dependency check | `mix xref graph --label compile-connected --fail-above 0` |
| Type check (slow; runs in CI, not in `precommit`) | `mix dialyzer` |
| Dependency vulnerabilities | `mix deps.audit` |
| Retired packages | `mix hex.audit` |
| Refresh AGENTS.md usage rules | `mix usage_rules.sync --yes` |
| Check those rules are current | `mix usage_rules.sync --check` |
| Search dependency docs | `mix usage_rules.search_docs "term" -p package` |
| Start Tidewave MCP server | `mix tidewave` |

Some of these only exist once the matching dep is installed; the `precommit`
alias in `mix.exs` is the authoritative list for this project.

## Conventions

- **Run `mix precommit` before declaring work finished.** Fix what it reports
  rather than narrowing the check or adding a suppression. If a check is
  genuinely wrong for this project, change the config in a separate commit and
  say why.
- **Format before committing.** CI enforces `mix format --check-formatted`.
- **No compiler warnings.** CI compiles with `--warnings-as-errors`, and tests
  run with `--warnings-as-errors` too — test files are held to the same bar.
- **Test-first when practical.** Add or update an ExUnit test that captures the
  behavior change, watch it fail, then implement. Use `async: true` in test
  modules unless they share global state (named processes, the database outside
  the SQL sandbox, Application env).
- **A test must be able to fail.** No test without an assertion, and no
  assertion that holds regardless of the code under test (`assert x == x`,
  or `assert is_map(result)` where every return value passes). If you can't
  write an assertion that would have failed before the change, the test isn't
  earning its keep.
- **Don't add dependencies to solve small problems.** The standard library
  covers date and time (`Date`, `Time`, `DateTime`, `Calendar`), and every new
  dep is one more thing CI has to audit. Ask before adding one.
- **Havoc builds on StreamData.** Base-package generators remain StreamData
  generators and ordinary properties delegate generation and shrinking to
  StreamData. Do not add a custom random/shrink loop, `Core.Runner`, or
  `Core.Scope`. The optional `havoc_proper` app delegates search to PropEr and
  must keep node-global Cover sessions serialized. Dynamic target providers
  describe inputs conservatively; consumers still own execution and fixtures.
- **Extend Muex, do not fork it.** `muex_security` contains focused custom
  mutators only. Muex remains responsible for traversal, compilation, test
  execution, optimization, and reports. Keep operators narrow enough that a
  surviving mutant asks a specific security-control question.
- **Pattern match at function heads** rather than with nested `case`/`cond`
  where it reads naturally; use `with` for chains of fallible calls. Never
  write a `case` whose only clauses are `true` and `false` — that's an `if`.
- **Let it crash where appropriate.** Don't defensively rescue exceptions in
  supervised processes; reserve `try/rescue` for genuine boundary concerns.
  Never `rescue` an exception only to log it and continue.
- **Typespecs on public functions** of library-style modules; Dialyzer runs in
  CI when `dialyxir` is installed. Name the arguments in the spec —
  `@spec fetch(user_id :: integer()) :: {:ok, t()} | {:error, term()}`.
- **Keep runtime deps out of compile time.** `mix xref graph --label
  compile-connected --fail-above 0` fails the build when a module edit starts
  triggering wide recompiles. The fix is usually to stop invoking a macro or
  referencing a struct at compile time across a context boundary.
- **Don't edit generated or vendored files** (`deps/`, `_build/`,
  `priv/static/assets/`, migration files that have already shipped).

## Framework and library guidelines

Generators — notably `mix phx.new` — ship their own `AGENTS.md`. On bootstrap
its guidance is merged into *this* file rather than left as a competing second
file: framework-specific rules go in a section below the conventions above,
and the machine-generated block goes at the bottom.

Anything between the `<!-- usage-rules-start -->` and `<!-- usage-rules-end -->`
markers at the end of this file is **generated from the installed
dependencies** by `mix usage_rules.sync`. Never hand-edit inside those markers:
the next sync overwrites it, and CI fails when the block is out of date. Put
your own guidance above the markers instead. After changing dependencies, run
`mix usage_rules.sync --yes` and commit the result.

That task prompts for confirmation, so it hangs if you run it bare in a
non-interactive shell. Always pass `--yes` (write the changes) or `--check`
(exit non-zero if stale, without writing).

## Versions

Erlang/Elixir versions are pinned in `.tool-versions` (used by asdf/mise
locally and by `erlef/setup-beam` in CI). Bump versions there, nowhere else.

<!-- usage-rules-start -->
<!-- usage_rules-start -->
## usage_rules usage
_A config-driven dev tool for Elixir projects to manage AGENTS.md files and agent skills from dependencies_

## Using Usage Rules

Many packages have usage rules, which you should *thoroughly* consult before taking any
action. These usage rules contain guidelines and rules *directly from the package authors*.
They are your best source of knowledge for making decisions.

## Modules & functions in the current app and dependencies

When looking for docs for modules & functions that are dependencies of the current project,
or for Elixir itself, use `mix usage_rules.docs`

```
# Search a whole module
mix usage_rules.docs Enum

# Search a specific function
mix usage_rules.docs Enum.zip

# Search a specific function & arity
mix usage_rules.docs Enum.zip/1
```


## Searching Documentation

You should also consult the documentation of any tools you are using, early and often. The best 
way to accomplish this is to use the `usage_rules.search_docs` mix task. Once you have
found what you are looking for, use the links in the search results to get more detail. For example:

```
# Search docs for all packages in the current application, including Elixir
mix usage_rules.search_docs Enum.zip

# Search docs for specific packages
mix usage_rules.search_docs Req.get -p req

# Search docs for multi-word queries
mix usage_rules.search_docs "making requests" -p req

# Search only in titles (useful for finding specific functions/modules)
mix usage_rules.search_docs "Enum.zip" --query-by title
```


<!-- usage_rules-end -->
<!-- usage_rules:elixir-start -->
## usage_rules:elixir usage
# Elixir Core Usage Rules

## Pattern Matching
- Use pattern matching over conditional logic when possible
- Prefer to match on function heads instead of using `if`/`else` or `case` in function bodies
- `%{}` matches ANY map, not just empty maps. Use `map_size(map) == 0` guard to check for truly empty maps

## Error Handling
- Use `{:ok, result}` and `{:error, reason}` tuples for operations that can fail
- Avoid raising exceptions for control flow
- Use `with` for chaining operations that return `{:ok, _}` or `{:error, _}`

## Common Mistakes to Avoid
- Elixir has no `return` statement, nor early returns. The last expression in a block is always returned.
- Don't use `Enum` functions on large collections when `Stream` is more appropriate
- Avoid nested `case` statements - refactor to a single `case`, `with` or separate functions
- Don't use `String.to_atom/1` on user input (memory leak risk)
- Lists and enumerables cannot be indexed with brackets. Use pattern matching or `Enum` functions
- Prefer `Enum` functions like `Enum.reduce` over recursion
- When recursion is necessary, prefer to use pattern matching in function heads for base case detection
- Using the process dictionary is typically a sign of unidiomatic code
- Only use macros if explicitly requested
- There are many useful standard library functions, prefer to use them where possible

## Function Design
- Use guard clauses: `when is_binary(name) and byte_size(name) > 0`
- Prefer multiple function clauses over complex conditional logic
- Name functions descriptively: `calculate_total_price/2` not `calc/2`
- Predicate function names should not start with `is` and should end in a question mark.
- Names like `is_thing` should be reserved for guards

## Data Structures
- Use structs over maps when the shape is known: `defstruct [:name, :age]`
- Prefer keyword lists for options: `[timeout: 5000, retries: 3]`
- Use maps for dynamic key-value data
- Prefer to prepend to lists `[new | list]` not `list ++ [new]`

## Mix Tasks

- Use `mix help` to list available mix tasks
- Use `mix help task_name` to get docs for an individual task
- Read the docs and options fully before using tasks

## Testing
- Run tests in a specific file with `mix test test/my_test.exs` and a specific test with the line number `mix test path/to/test.exs:123`
- Limit the number of failed tests with `mix test --max-failures n`
- Use `@tag` to tag specific tests, and `mix test --only tag` to run only those tests
- Use `assert_raise` for testing expected exceptions: `assert_raise ArgumentError, fn -> invalid_function() end`
- Use `mix help test` to for full documentation on running tests

## Debugging

- Use `dbg/1` to print values while debugging. This will display the formatted value and other relevant information in the console.

<!-- usage_rules:elixir-end -->
<!-- usage_rules:otp-start -->
## usage_rules:otp usage
# OTP Usage Rules

## GenServer Best Practices
- Keep state simple and serializable
- Handle all expected messages explicitly
- Use `handle_continue/2` for post-init work
- Implement proper cleanup in `terminate/2` when necessary

## Process Communication
- Use `GenServer.call/3` for synchronous requests expecting replies
- Use `GenServer.cast/2` for fire-and-forget messages.
- When in doubt, use `call` over `cast`, to ensure back-pressure
- Set appropriate timeouts for `call/3` operations

## Fault Tolerance
- Set up processes such that they can handle crashing and being restarted by supervisors
- Use `:max_restarts` and `:max_seconds` to prevent restart loops

## Task and Async
- Use `Task.Supervisor` for better fault tolerance
- Handle task failures with `Task.yield/2` or `Task.shutdown/2`
- Set appropriate task timeouts
- Use `Task.async_stream/3` for concurrent enumeration with back-pressure

<!-- usage_rules:otp-end -->
<!-- usage-rules-end -->
