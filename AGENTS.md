# Agent Guidelines

## About this repo

This repo starts life as an Elixir project *template*: infrastructure only, no
mix project. If there is no `mix.exs` yet, the project hasn't been bootstrapped —
see README.md for the bootstrap steps, and don't try to run mix tasks.
Once bootstrapped, delete this paragraph and fill in the "Project overview"
section below.

## Project overview

<!-- After bootstrap: one paragraph on what this app does, plus anything
     non-obvious about its architecture (umbrella? Phoenix? OTP apps?). -->

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
| Run one test file | `mix test test/path/to/file_test.exs` |
| Run one test | `mix test test/path/to/file_test.exs:LINE` |
| Format | `mix format` |
| Lint | `mix credo --strict` |
| Compile-time dependency check | `mix xref graph --label compile-connected --fail-above 0` |
| Type check (slow; runs in CI, not in `precommit`) | `mix dialyzer` |
| Dependency vulnerabilities | `mix deps.audit` |
| Retired packages | `mix hex.audit` |
| Phoenix security scan | `mix sobelow --exit --skip` |
| Refresh AGENTS.md usage rules | `mix usage_rules.sync --yes` |
| Check those rules are current | `mix usage_rules.sync --check` |
| Search dependency docs | `mix usage_rules.search_docs "term" -p package` |

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
- **If this repo has both `.github/workflows/` and `.forgejo/workflows/`,
  they are not copies.** The Forgejo one installs the BEAM by hand, references
  actions by full URL, and reaches services by container name — every
  difference is deliberate and documented in README.md. When you change one
  pipeline, decide consciously whether the other needs the same change; don't
  mirror it mechanically. Note that `actionlint` cannot check the Forgejo file,
  so verify edits there by hand.

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
