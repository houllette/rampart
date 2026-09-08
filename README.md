# elixir_template

A GitHub template for starting Elixir projects without re-doing the boring
parts. It deliberately contains **no mix project** — `mix new`, `mix phx.new`,
and friends differ too much per project to pre-bake, and all of them run fine
on top of this repo. What it does contain is everything generator-agnostic:

- **CI** (`.github/workflows/ci.yml`) — compile and test with
  warnings-as-errors, format check, compile-time dependency check, unused
  dependency check, a dedicated security job, auto-detected Credo / Dialyzer /
  ex_doc / Sobelow / usage-rules steps, and an actionlint pass over the
  workflows themselves. It skips itself gracefully until a mix project exists,
  so the bare template stays green.
- **Version pinning** (`.tool-versions`) — single source of truth for
  Erlang/Elixir, read by asdf/mise locally and `erlef/setup-beam` in CI.
- **Agent guidance** (`AGENTS.md`, with `CLAUDE.md` pointing at it) and Claude
  Code permissions for common mix tasks (`.claude/settings.json`).
- **A `/bootstrap` skill** (`.claude/skills/bootstrap/`) — run it in Claude
  Code and it interviews you about the project, picks the right generator
  command, runs it, merges the generator's `AGENTS.md` into this one, wires up
  Tidewave MCP, scaffolds whatever the interview surfaced (Oban, clustering,
  `phx.gen.auth`), and does the whole post-bootstrap checklist below for you.
  It starts by asking what the codebase is *for* — that answer becomes the
  README description and the `AGENTS.md` project overview, and pre-selects the
  defaults in the rounds that follow.
- **Forgejo CI** (`.forgejo/workflows/ci.yml`) — the same pipeline for
  self-hosted Forgejo instances. Not a copy: see [Forgejo](#forgejo) for the
  differences, which are load-bearing.
- **Repo hygiene** — Elixir/Phoenix `.gitignore`, `.editorconfig`, Dependabot
  for Hex + GitHub Actions (plus `renovate.json` for the Forgejo side), PR
  templates for both forges, Conventional Commits check on PR titles.

The guiding idea, borrowed from [Guarding Against AI
Drift](https://mikezornek.com/posts/2026/7/guarding-against-ai-drift/): the way
to keep generated code from eroding a codebase's standards is to make the
standards *executable*. One `mix precommit` alias, mirrored in CI, that an
agent is told to run before it claims to be finished.

## Starting a new project

1. **Create the repo from this template**

   ```sh
   gh repo create my_app --template <owner>/elixir_template --private --clone
   cd my_app
   ```

   Then either run `/bootstrap` in Claude Code (which automates steps 2–8),
   or continue manually:

2. **Run a generator in place** (pick one):

   ```sh
   mix new . --app my_app --sup          # plain OTP app
   mix phx.new . --app my_app            # Phoenix (add --no-ecto etc. to taste)
   mix igniter.new my_app ...            # igniter-based setups
   ```

   When the generator asks to overwrite `README.md`, say yes (then rewrite it
   for your project). If it asks about `.gitignore`, **keep the template's**
   or merge — the generated one is a subset. If it asks about `AGENTS.md`,
   **keep the template's** and merge by hand — see step 5.

3. **Add the QA deps** the CI auto-detects:

   ```elixir
   # mix.exs deps
   {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
   {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
   {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
   {:ex_doc, "~> 0.40", only: [:dev, :test], runtime: false},
   {:usage_rules, "~> 1.2", only: [:dev, :test], runtime: false},
   {:sobelow, "~> 0.14", only: [:dev, :test], runtime: false},   # Phoenix only
   ```

   `usage_rules` needs `:test` in that list even though it's a dev tool — CI
   runs with `MIX_ENV=test`, and a `:dev`-only dep makes the task unavailable
   there.

   Each one turns on a CI step by its presence in `mix.exs`; drop the ones you
   don't want. `ex_doc` also gives you `mix docs --warnings-as-errors`, which
   turns broken doc references into build failures instead of quiet rot.

4. **Wire up the `precommit` alias and Dialyzer PLT path** in `mix.exs`.
   `precommit` is the single command agents and humans run before finishing;
   CI runs the same checks:

   ```elixir
   def project do
     [
       # ...
       dialyzer: [
         plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
         # Required for Phoenix: elixirc_paths(:test) compiles test/support,
         # and CI runs Dialyzer with MIX_ENV=test. Without :ex_unit the run
         # fails with unknown_function against ExUnit.Callbacks and
         # ExUnit.CaseTemplate in conn_case.ex / data_case.ex.
         plt_add_apps: [:ex_unit, :mix],
         ignore_warnings: ".dialyzer_ignore.exs"
       ],
       aliases: aliases()
     ]
   end

   # Tests need MIX_ENV=test; without this the alias runs in :dev.
   def cli do
     [preferred_envs: [precommit: :test]]
   end

   defp aliases do
     [
       precommit: [
         "deps.unlock --check-unused",
         # The audits read mix.lock only, and must run before compile.
         "hex.audit",
         "deps.audit",
         "compile --warnings-as-errors",
         "format",
         "credo --strict",
         "usage_rules.sync --yes",
         "xref graph --label compile-connected --fail-above 0",
         # "sobelow --exit --skip",   # Phoenix only
         # "docs --warnings-as-errors",
         "test --warnings-as-errors"
       ]
     ]
   end
   ```

   `mix phx.new` already generates `aliases/0`, `cli/0`, and a shorter
   `precommit` — **extend those, don't add a second alias.** Dialyzer stays out
   of `precommit` (too slow for an edit loop) and runs in CI on its own.

   `usage_rules.sync` is Igniter-backed and **prompts for confirmation**, which
   hangs any non-interactive run. Always pass `--yes` (fix in place) or
   `--check` (fail without writing, which is what CI uses).

   The `hex.audit`-before-`compile` ordering is load-bearing. `mix compile`
   drops the Hex archive from the code path for the remainder of the alias, so
   a later `mix hex.audit` in the same alias dies with `The task "hex.audit"
   could not be found` — a confusing failure that has nothing to do with your
   dependencies. `mix deps.audit` comes from a regular dep and isn't affected,
   but it reads only `mix.lock` too, so it sits alongside. CI is unaffected: it
   runs the audits in a separate job.

   Then `mix credo.gen.config` for a `.credo.exs`, and add `/priv/plts/` to
   `.gitignore`.

   **A freshly generated Phoenix app does not pass this alias.** Verified
   against `phx.new` 1.8.9 — two things fail, and both deserve a real fix
   rather than a suppression:

   - `mix credo --strict` (exit 2) — three `Design.AliasUsage` hits on
     fully-qualified calls in generated code. Add `alias Phoenix.HTML.Form` to
     `core_components.ex` and `alias Ecto.Adapters.SQL.Sandbox` to
     `test/support/data_case.ex`, then use the short names. Clears all three.
   - `mix sobelow --exit --skip` (exit 1) — `Config.CSP: Missing
     Content-Security-Policy`. Stock Phoenix ships no CSP; add one to the
     `:browser` pipeline:

     ```elixir
     plug :put_secure_browser_headers, %{
       "content-security-policy" =>
         "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:"
     }
     ```

     Tighten it for your app — this baseline covers LiveView's socket and
     Tailwind's injected styles, but any CDN or external asset needs adding.

   **Dialyzer needs two things too** (it runs in CI, not in `precommit`).
   Verified on a stock `phx.new` app: without `plt_add_apps: [:ex_unit, :mix]`
   it exits 2 with seven `unknown_function` warnings against `ExUnit.Callbacks`
   and `ExUnit.CaseTemplate`. With it, one warning remains — a `pattern_match`
   in `deps/phoenix/lib/phoenix/router.ex`, i.e. inside a dependency, not
   fixable from your code. Skip that one specifically rather than disabling the
   job:

   ```elixir
   # .dialyzer_ignore.exs
   [
     # Phoenix's router macros expand into code Dialyzer can't narrow. The
     # warning is attributed to the dependency, so it isn't ours to fix.
     {"deps/phoenix/lib/phoenix/router.ex", :pattern_match}
   ]
   ```

   That yields `Total errors: 1, Skipped: 1` and a clean exit.

   `mix xref graph --label compile-connected --fail-above 0`,
   `mix docs --warnings-as-errors`, `mix deps.audit`, and `mix hex.audit` all
   pass on a stock generated app.

5. **Merge the generator's `AGENTS.md`.** Recent `mix phx.new` writes its own
   `AGENTS.md`, and its advice is good — but two agent files in one repo means
   one of them gets ignored. Fold it into the template's single `AGENTS.md`:

   - Keep the template's **structure** (Project overview → Commands →
     Conventions → Versions).
   - Move the generator's framework prose (Phoenix v1.8, JS/CSS, UI/UX
     sections) into a **"Framework and library guidelines"** section, below
     Conventions.
   - Move the whole `<!-- usage-rules-start -->` … `<!-- usage-rules-end -->`
     block **verbatim to the bottom of the file**. It's generated from your
     deps — never hand-edit inside the markers.
   - Reconcile duplicates in favour of the template: the generator says "use
     `mix precommit`", and after step 4 that's the same alias the Commands
     table names.

   With `usage_rules` installed (step 3), keep that block current by declaring
   it in `mix.exs` and re-syncing after dependency changes:

   ```elixir
   def project do
     [
       # ...
       usage_rules: [file: "AGENTS.md", usage_rules: :all]
     ]
   end
   ```

   ```sh
   mix usage_rules.sync --yes
   ```

   CI runs `mix usage_rules.sync --check`, which fails without writing, so a
   Dependabot bump can't silently leave your agents reading stale library
   rules.

6. **Wire up Tidewave MCP.** This is what lets an agent talk to the running app
   rather than reason about it from source: evaluate code in the live app, read
   its logs, query the dev database, and pull docs pinned to your exact locked
   versions.

   ```elixir
   # mix.exs deps
   {:tidewave, "~> 0.8", only: :dev},
   ```

   In `lib/APP_web/endpoint.ex`, immediately **above** the
   `if code_reloading? do` block:

   ```elixir
   if Mix.env() == :dev do
     plug Tidewave
   end
   ```

   For a non-Phoenix project, serve the plug yourself instead — add
   `{:bandit, "~> 1.0", only: :dev}` and an alias:

   ```elixir
   tidewave: "run --no-halt -e 'Agent.start(fn -> Bandit.start_link(plug: Tidewave, port: 4000) end)'"
   ```

   Then commit a `.mcp.json` at the repo root so everyone who clones the repo
   gets the server:

   ```json
   {
     "mcpServers": {
       "tidewave": {
         "type": "http",
         "url": "http://localhost:4000/tidewave/mcp"
       }
     }
   }
   ```

   The `"type"` field is required — Claude Code treats a `url` entry without it
   as a stdio server and skips it.

   Two things that look like breakage but aren't: a project-scoped `.mcp.json`
   stays *pending approval* until you approve it in an interactive `claude`
   session, and the server only answers while the app is actually running
   (`mix phx.server`, or `mix tidewave`). `/mcp` in Claude Code confirms the
   connection.

   Tidewave binds to localhost and ships no authentication, which is why
   `:allow_remote_access` should stay off. It also handles the CSP from step 4
   on its own, adding `unsafe-eval` in dev only.

7. **Trim CI to fit.** Delete the CI you don't use — `.github/` (with
   `dependabot.yml`) or `.forgejo/` (with `renovate.json`); keeping both is
   fine. If the project doesn't use Ecto + Postgres, delete the `services:`
   block from whichever you keep. Delete the `pr-title` job if you don't want
   Conventional Commits enforced on PR titles. Everything else turns itself on
   or off based on `mix.exs`, so leave it alone.

8. **Update the docs.** Rewrite this README, and fill in the "Project
   overview" section of `AGENTS.md` (deleting its template note).

## Forgejo

`.forgejo/workflows/ci.yml` runs the same pipeline as the GitHub one, but it is
**not** a copy, and the differences are not cosmetic. If you edit one, don't
mechanically mirror the change into the other.

Forgejo reads PR templates from `.forgejo/`, `.gitea/`, `.github/`, or the repo
root, so `.forgejo/PULL_REQUEST_TEMPLATE.md` is a straight copy. Dependabot has
no Forgejo equivalent — `renovate.json` covers that side with the same weekly,
grouped shape. **It does nothing until Renovate is actually enabled on your
instance**; it's inert config, not a running bot.

> On the template repo itself, Dependabot's `hex` job fails every run with
> `/mix.exs not found`. That's expected — there's no mix project until you
> bootstrap — and it fixes itself on the first generated `mix.exs`. The
> `github-actions` job passes throughout.

### erlef/setup-beam cannot work on a default runner

This is the trap worth knowing before you spend CI cycles on it. setup-beam
picks its prebuilt tarball by looking up `$ImageOS`. `forgejo-runner` embeds
`act`, which derives that variable from the job's label and injects it into the
job environment (`pkg/runner/run_context.go`):

```go
if platformName == "ubuntu-latest" {
    env["ImageOS"] = "ubuntu20"        // hardcoded
} else {
    platformName = strings.SplitN(strings.Replace(platformName, `-`, ``, 1), `.`, 2)[0]
    env["ImageOS"] = platformName      // "docker" -> "docker"
}
```

So `runs-on: docker` yields `"docker"`, which setup-beam's map rejects, and
`ubuntu-latest` yields `"ubuntu20"`, which it maps to `ubuntu-20.04` with a
deprecation warning and then 404s — builds.hex.pm has no `ubuntu-20.04`
artifacts for a modern OTP (OTP 29 there is a 404; ubuntu-22.04 and 24.04 are
200). setup-beam exposes **no input** to override the OS, and setting `ImageOS:`
at workflow or step level is a no-op because the runner's injection wins.

That's why the workflow installs the BEAM with a `run:` step instead, reading
`.tool-versions` so it stays the single source of truth. Two layout facts worth
not re-deriving: the OTP tarball has a single `OTP-<ver>/` root containing
`Install` (hence `--strip-components=1`), and the Elixir zip extracts flat.
`BEAM_TARGET` must match the container image.

If your instance *does* have a runner labelled `ubuntu-22.04` or `ubuntu-24.04`,
you can use setup-beam with that label as `runs-on` and drop `container:`.
Check before assuming:

```
GET /api/v1/repos/{owner}/{repo}/actions/runners   → .runners[].labels
```

### The rest of the differences

- **Don't switch to a `hexpm/elixir` image.** Those have no `node`, and the
  runner runs `checkout`/`cache` as JS actions inside the container.
  `ghcr.io/catthehacker/ubuntu:act-22.04` is the standard stand-in.
- **Actions are referenced by full URL.** Forgejo resolves a bare `owner/repo`
  against the instance's `DEFAULT_ACTIONS_URL`, which varies. Verify a tag
  exists before repinning: `git ls-remote --tags https://code.forgejo.org/actions/cache`.
- **No `permissions:` block.** Forgejo ignores it and warns once per job on
  every run. Use Settings → Actions → Authorized Integrations.
- **Services are reached by name, not a port mapping**, because the job runs in
  a container. The workflow sets `DB_HOST: postgres`, which needs a matching
  app-side change the GitHub path doesn't:
  ```elixir
  # config/test.exs
  hostname: System.get_env("DB_HOST", "localhost"),
  ```
- **Cache keys** use `hashFiles('.tool-versions')` and `hashFiles('mix.lock')`,
  since there are no `steps.beam.outputs.*` without setup-beam. If your
  instance's cache server predates the `actions/cache@v6` API, pin `@v4`.
- **No semantic-PR-title job** — that action talks to the GitHub API.

### Known gap: the Forgejo workflow is unlinted

actionlint rejects full-URL `uses:` as malformed and doesn't recognise the
`docker` label, and neither is fixable via `actionlint.yaml`. Bare `actionlint`
only scans `.github/workflows/`, so the GitHub job stays green and
`.forgejo/workflows/ci.yml` is simply never checked. After editing it, at
minimum confirm it parses:

```sh
python3 -c "import yaml; yaml.safe_load(open('.forgejo/workflows/ci.yml'))"
```

You can also exercise the install script in the same image CI uses:

```sh
docker run --rm --platform linux/amd64 \
  -v "$PWD/.tool-versions:/w/.tool-versions:ro" -w /w \
  -e BEAM_TARGET=ubuntu-22.04 ghcr.io/catthehacker/ubuntu:act-22.04 bash -c '...'
```

On Apple Silicon the BEAM crashes on **execution** under qemu with a `user_drv`
/ `nouser` error. That's emulation, not the script — the VM booted far enough to
start the tty driver. Check artifacts instead: `file` on `erts-*/bin/beam.smp`
should report `x86-64`, and `ldd` should list nothing as missing. There are no
arm64 `ubuntu-22.04` builds on builds.hex.pm, so a native test isn't possible.

## Capabilities the bootstrap interview asks about

None of these are pre-installed — they're decisions, and the wrong default is
worse than no default. `/bootstrap` asks about each and wires up whichever you
pick; the notes below are what it applies.

**Background jobs — Oban** (`{:oban, "~> 2.23"}`). Needs Ecto. Pick the engine
to match the database (`Basic` for Postgres, `Lite` for SQLite, `Dolphin` for
MySQL). The setting that matters most is in `config/test.exs`:

```elixir
config :my_app, Oban, testing: :manual
```

Without it, your tests execute jobs for real. With it, assert with
`assert_enqueued/1` that a job was scheduled, and reach for
`Oban.Testing.with_testing_mode(:inline, fn -> ... end)` only in the rare test
that needs the job to actually run.

**Clustering.** Four different answers, and only two of them need a dependency:

| Need | Answer |
| --- | --- |
| Single node | Nothing |
| Multiple nodes, DNS discovery | **Already done** — `phx.new` puts `DNSCluster` in the supervision tree and reads `DNS_CLUSTER_QUERY` from `runtime.exs`. Covers Fly.io and Kubernetes headless services. |
| Multiple nodes, other discovery | `{:libcluster, "~> 3.5"}` with a topology in config (gossip, EPMD, Kubernetes API) |
| Distributed processes or state | `{:horde, "~> 0.10"}` on top of discovery — or `highlander`, if all you need is one singleton process |

Worth knowing before you add anything: Phoenix PubSub and Presence already work
across a cluster as soon as nodes connect, and Oban already coordinates through
the database. Neither is a reason to add Horde. And Horde is *eventually
consistent* — under a partition you can briefly get duplicate processes, which
the registry kills once it notices.

**Testing a cluster** — `{:local_cluster, "~> 2.1", only: [:test]}`, with
multi-node tests tagged `@tag :distributed` and excluded from `mix test`
(peers are slow to spawn). CI runs `mix test.distributed` automatically once
`:local_cluster` appears in `mix.exs`. One real cost to accept knowingly:
LocalCluster requires `mix test --no-start`, because the node must be renamed
before the app tree boots — that changes how the *whole* suite starts, not just
the distributed tests.

## Optional extras

Not enabled by default — each is a real opinion, so opt in deliberately:

- **Credo check packs.** Stock Credo doesn't know about the failure modes
  specific to generated code. These add checks that do:

  ```elixir
  {:ex_slop, "~> 0.4", only: [:dev, :test], runtime: false},
  {:jump_credo_checks, "~> 0.4", only: [:dev, :test], runtime: false},
  {:oeditus_credo, "~> 0.8", only: [:dev, :test], runtime: false},
  ```

  The high-value ones to enable in `.credo.exs`: `VacuousTest`,
  `TestHasNoAssertions`, and `WeakAssertion` (tests that pass without proving
  anything); `UnmanagedTask`, `SyncOverAsync`, and `SwallowingException`
  (concurrency and error-handling anti-patterns).
- **`boundary`** — enforces context boundaries beyond Elixir's module-level
  visibility, so nothing reaches into a context's internals.
- **`excoveralls`** — coverage, best kept as a local report rather than a CI
  gate; a coverage percentage is easy to satisfy without testing anything.
- **`phoenix_test`** — user-flow-shaped assertions that stay readable, which
  makes generated tests more likely to survive review.

## Versions

Pinned in [`.tool-versions`](.tool-versions). Bump there; local tooling
(asdf/mise) and CI both follow it. Elixir builds are OTP-specific — keep the
`-otp-NN` suffix in sync with the Erlang major version.
