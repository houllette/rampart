---
name: bootstrap
description: Bootstrap this Elixir template into a real project. Interviews the user about what they're building (purpose, background jobs, clustering, auth), picks and runs the right generator, merges the generator's AGENTS.md, wires up Tidewave MCP, the precommit alias, Credo/Dialyzer/security tooling, and any clustering or Oban scaffolding. Use when the repo has no mix.exs yet and the user wants to start their project.
argument-hint: "[optional app name]"
---

# Bootstrap an Elixir project from this template

Turn this template repo into a real Elixir project. The interview drives three
things: which generator runs, which capabilities get scaffolded, and what the
README and `AGENTS.md` actually say about the project.

## 1. Preflight

- If `mix.exs` already exists in the repo root, stop and tell the user the
  project is already bootstrapped.
- Confirm `mix` is available and the versions in `.tool-versions` are
  installed (`mix --version`). If not, suggest `mise install` / `asdf install`
  and stop.

## 2. Ask what this is for (plain prose, not AskUserQuestion)

Before any multiple choice, ask in your own message and wait for a reply:

> Before I pick a generator — in a sentence or two, what is this codebase for?
> What does it do, and who or what consumes it? If you already know roughly
> where it'll run (a single VM, Fly.io, Kubernetes) or how much traffic it
> should take, mention that too.

This answer is load-bearing. Keep it verbatim and use it to:

- **pre-select** the recommended option in every later round, so the interview
  is mostly confirmation rather than interrogation;
- **write** the README description and the `AGENTS.md` "Project overview"
  in step 11 — those get the user's own framing, not boilerplate.

If the reply is vague ("a web app"), ask **one** follow-up, then move on.

## 3. Round 1 — project shape

Use AskUserQuestion. Skip the app-name question if the user passed a name as
the skill argument.

1. **Project type** — options:
   - "Phoenix web app" — full phx.new: HTML, LiveView, assets
   - "Phoenix JSON API" — phx.new `--no-html --no-assets`
   - "Supervised OTP app" — `mix new --sup`; long-running processes, no web layer
   - "Library" — plain `mix new`; code meant to be published/embedded
2. **App name** — offer the repo directory name converted to snake_case as
   the recommended option. Must match `^[a-z][a-z0-9_]*$`. If the user picks
   "Other", validate what they type.

## 4. Round 2 — Phoenix specifics and forge

Ask the forge question for **every** project type; the other two only for
Phoenix.

1. **Forge** — check `git remote -v` first and lead with what it implies: if the
   remote host isn't `github.com`, recommend Forgejo. Options: "GitHub Actions",
   "Forgejo Actions", "Both". The template ships both `.github/` and
   `.forgejo/`; this answer decides which survives step 9.
2. **Database** (Phoenix only) — Postgres (recommended, matches CI's service
   container), SQLite (`--database sqlite3`), MySQL (`--database mysql`), or
   none (`--no-ecto`).
3. **Extras** (Phoenix only, multiSelect) — "Binary IDs (--binary-id)",
   "Umbrella app (--umbrella)", "Skip mailer (--no-mailer)", "Skip dashboard
   (--no-dashboard)".

## 5. Round 3 — capabilities

Skip entirely for "Library". Ask these together in one AskUserQuestion call,
with your recommendation (from step 2) listed first.

1. **Background work** — omit the Oban option if the user chose `--no-ecto`,
   since Oban needs a repo:
   - "Oban" — durable, DB-backed jobs; survives restarts and deploys, and
     coordinates across nodes through the database
   - "Tasks and GenServers only" — in-process, fire-and-forget; work is lost
     if the node dies
   - "None yet"

2. **Clustering** — read the options carefully, they are not a severity scale:
   - "Single node" — no clustering
   - "Multiple nodes, DNS discovery" — **already handled**: `phx.new` puts
     `DNSCluster` in the supervision tree and reads `DNS_CLUSTER_QUERY` in
     `runtime.exs`. Covers Fly.io and Kubernetes headless services with no new
     dependency.
   - "Multiple nodes, other discovery" — libcluster, for gossip, EPMD, or the
     Kubernetes API instead of DNS
   - "Distributed processes or state" — a process that must exist exactly once
     cluster-wide, or state that must survive a node dying. Adds Horde (or
     Highlander) *on top of* discovery.

   Tell them plainly, if it's relevant: Phoenix PubSub and Presence already
   work across a cluster the moment nodes connect, and Oban already coordinates
   through Postgres. Those are not reasons to add Horde.

3. **Authentication** (Phoenix types with Ecto only):
   - "`mix phx.gen.auth`" — scaffolds registration, sessions, password reset
   - "External identity provider" — OAuth/OIDC/SSO, wired later
   - "None yet"

Stop after this round. Anything else stays at generator defaults.

## 6. Compose and run the generator

| Type | Command |
| --- | --- |
| Library | `mix new APP` |
| Supervised OTP app | `mix new APP --sup` |
| Phoenix web app | `mix phx.new APP [db/extras flags]` |
| Phoenix JSON API | `mix phx.new APP --no-html --no-assets [db/extras flags]` |

For Phoenix: check the archive first (`mix archive` lists `phx_new`); install
with `mix archive.install hex phx_new --force` if missing.

**Never run the generator directly in the repo root** — generators prompt
interactively on file conflicts, which hangs in a non-interactive shell.
Instead:

1. Tell the user the exact command you settled on.
2. Run it in the scratchpad directory (for phx.new, answer the "fetch and
   install dependencies?" prompt by piping: `echo n | mix phx.new ...`).
3. Merge the generated `APP/` directory into the repo root:
   - `README.md`: replace the template's with the generated one for now
     (it gets rewritten in step 11).
   - `.gitignore`: keep the template's; diff against the generated one and
     append any lines the template lacks.
   - `AGENTS.md`: **do not copy it over.** Leave the generated one in the
     scratchpad and handle it in step 10 — the template's is the one that
     survives.
   - Everything else: copy over (e.g. `rsync -a --exclude .git --exclude AGENTS.md`
     from the generated dir), then delete the temp copy.
4. Run `mix deps.get`, then `mix compile` and `mix test` to prove the
   generated project is healthy before touching it further.
5. If they chose `mix phx.gen.auth`, run it now, before any other wiring:
   `mix phx.gen.auth Accounts User users` (add `--no-live` for the JSON API
   type). Then `mix deps.get` and `mix ecto.migrate`.
6. **If `--no-mailer` was chosen**, open the generated `AGENTS.md` and delete
   its "use the already included and available `:req`" bullet. `phx.new` pulls
   `:req` in alongside Swoosh, so `--no-mailer` drops *both* — but the
   generated `AGENTS.md` still claims Req is available. Left alone, an agent
   will write `Req.get!/1` against a module that isn't in `mix.exs`. Verified
   against phx.new 1.8.9: stock deps **do** include `{:req, "~> 0.5"}`, so
   leave that bullet alone in every other case. Check `mix.exs` rather than
   assuming either way.

## 7. Wire up Tidewave MCP

Do this for every project — it's what lets an agent talk to the running app
instead of guessing about it (evaluate code in the live app, read its logs,
query the dev database, get docs pinned to your exact locked versions).

**Phoenix projects:**

1. Add to deps: `{:tidewave, "~> 0.8", only: :dev}`
2. In `lib/APP_web/endpoint.ex`, immediately **above** the `if code_reloading? do`
   block:
   ```elixir
   if Mix.env() == :dev do
     plug Tidewave
   end
   ```

**Non-Phoenix projects** (OTP app or library) — serve the plug yourself:

```elixir
# deps
{:tidewave, "~> 0.8", only: :dev},
{:bandit, "~> 1.0", only: :dev},

# aliases
tidewave: "run --no-halt -e 'Agent.start(fn -> Bandit.start_link(plug: Tidewave, port: 4000) end)'"
```

Then, for every project type, write `.mcp.json` in the repo root so the server
is configured for anyone who clones it (it is committed, not ignored):

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

The `"type"` field is required — Claude Code reads a `url` entry with no `type`
as a stdio server and skips it. Match the port to the app's actual dev port if
it isn't 4000.

Tell the user two things, or they'll think it's broken:

- A project-scoped `.mcp.json` is **pending approval** until they approve it in
  an interactive `claude` session; it won't connect on its own.
- The server only answers **while the app is running** (`mix phx.server`, or
  `mix tidewave` for non-Phoenix). `/mcp` in Claude Code confirms the
  connection.

Tidewave binds to localhost only and ships no authentication — leave
`:allow_remote_access` alone.

Tidewave and the Content-Security-Policy added in step 9 don't conflict — it
adds `unsafe-eval` to `script-src` and drops `frame-ancestors` by itself, in
dev only. Nothing to reconcile.

## 8. Wire up the selected capabilities

### Oban (if chosen)

1. Dep: `{:oban, "~> 2.23"}`
2. `config/config.exs` — pick the engine from the database chosen in round 2
   (`Oban.Engines.Basic` for Postgres, `Oban.Engines.Lite` for SQLite,
   `Oban.Engines.Dolphin` for MySQL):
   ```elixir
   config :my_app, Oban,
     engine: Oban.Engines.Basic,
     queues: [default: 10],
     repo: MyApp.Repo
   ```
3. Migration: `mix ecto.gen.migration add_oban_jobs_table`, then
   ```elixir
   def up, do: Oban.Migration.up(version: 14)
   def down, do: Oban.Migration.down(version: 1)
   ```
   Then `mix ecto.migrate`.
4. Supervision tree, after the Repo:
   `{Oban, Application.fetch_env!(:my_app, Oban)}`
5. **`config/test.exs`: `config :my_app, Oban, testing: :manual`.** Without
   this, tests execute jobs for real. With it, use `Oban.Testing`'s
   `assert_enqueued/1` to assert a job was *scheduled*, and wrap the rare test
   that needs the job to actually run in
   `Oban.Testing.with_testing_mode(:inline, fn -> ... end)`.
6. Add `use Oban.Testing, repo: MyApp.Repo` to `test/support/data_case.ex`.

### Clustering

**"Multiple nodes, DNS discovery"** — nothing to install. Confirm
`{DNSCluster, query: Application.get_env(:my_app, :dns_cluster_query) || :ignore}`
is in the supervision tree and point the user at `DNS_CLUSTER_QUERY` in
`runtime.exs`. Tell them the nodes also need a shared Erlang cookie and
`RELEASE_DISTRIBUTION=name`, which their release tooling sets.

**"Multiple nodes, other discovery"** — add `{:libcluster, "~> 3.5"}`, put the
topology in config so it can differ per environment, and start the supervisor
*before* anything that assumes peers:

```elixir
# config/runtime.exs — strategy depends on where it runs; Gossip suits a flat
# network, Cluster.Strategy.Kubernetes uses the API instead of DNS.
config :libcluster,
  topologies: [
    my_app: [strategy: Cluster.Strategy.Gossip]
  ]

# lib/my_app/application.ex — first in the children list
{Cluster.Supervisor,
 [Application.get_env(:libcluster, :topologies, []), [name: MyApp.ClusterSupervisor]]}
```

**"Distributed processes or state"** — add discovery as above, then Horde
(`{:horde, "~> 0.10"}`): `Horde.Registry` for cluster-wide unique names and
`Horde.DynamicSupervisor` for processes that should be redistributed when a
node dies. Two things the user must hear before they build on it:

- Horde is **eventually consistent**. Under a partition you can briefly get
  duplicate processes; the registry kills duplicates when it notices. Choose
  `Horde.UniformQuorumDistribution` if it is safer for the app to shut down a
  minority partition than to run twice.
- If all they need is one singleton process cluster-wide, `highlander` is a far
  smaller answer than Horde. Say so.

**Testing a cluster** (any multi-node answer). This has a cost the user must
opt into knowingly, so explain it rather than just doing it:

1. `{:local_cluster, "~> 2.1", only: [:test]}`
2. `test/test_helper.exs`:
   ```elixir
   :ok = LocalCluster.start()
   Application.ensure_all_started(:my_app)
   ExUnit.configure(exclude: [:distributed])
   ExUnit.start()
   ```
3. `mix.exs` — LocalCluster needs `--no-start`, because the node has to be
   renamed before the app tree boots. Phoenix already defines a `test` alias,
   so **extend it, don't replace it**:
   ```elixir
   test: ["ecto.create --quiet", "ecto.migrate --quiet", "test --no-start"],
   "test.distributed": ["test --only distributed"]
   ```
   Flag the tradeoff explicitly: `--no-start` changes how the *whole* suite
   boots, not just the distributed tests.
4. Tag multi-node tests `@tag :distributed`. They're excluded from `mix test`
   by default because spawning peers is slow; CI picks them up automatically
   via a separate step once `:local_cluster` is in `mix.exs`.

## 9. Wire up QA tooling

1. Add to deps. Each switches on a CI step by its presence; include `sobelow`
   only for Phoenix:
   ```elixir
   {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
   {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
   {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
   {:ex_doc, "~> 0.40", only: [:dev, :test], runtime: false},
   {:usage_rules, "~> 1.2", only: [:dev, :test], runtime: false},
   {:sobelow, "~> 0.14", only: [:dev, :test], runtime: false},
   ```
   `usage_rules` must include `:test` — CI runs with `MIX_ENV=test` and a
   `:dev`-only dep makes the task unavailable there.
2. In `project/0`, add:
   ```elixir
   dialyzer: [
     plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
     plt_add_apps: [:ex_unit, :mix],
     ignore_warnings: ".dialyzer_ignore.exs"
   ],
   usage_rules: [file: "AGENTS.md", usage_rules: :all],
   ```
   Both extras are **required for Phoenix**, and Dialyzer only runs in CI, so
   getting them wrong shows up as a red build after you've moved on:
   - `plt_add_apps` — `elixirc_paths(:test)` compiles `test/support`, and CI
     runs Dialyzer under `MIX_ENV=test`. Without `:ex_unit` in the PLT, a stock
     generated app exits 2 with seven `unknown_function` warnings against
     `ExUnit.Callbacks` and `ExUnit.CaseTemplate`.
   - `ignore_warnings` — one warning survives that, a `pattern_match` inside
     `deps/phoenix/lib/phoenix/router.ex`. It's in a dependency and not yours to
     fix. Write `.dialyzer_ignore.exs` with exactly that one entry; do not
     broaden it and do not drop the Dialyzer job:
     ```elixir
     [
       # Phoenix's router macros expand into code Dialyzer can't narrow. The
       # warning is attributed to the dependency, so it isn't ours to fix.
       {"deps/phoenix/lib/phoenix/router.ex", :pattern_match}
     ]
     ```
     Verified end state: `Total errors: 1, Skipped: 1`, exit 0.
3. Add (or extend) the `precommit` alias — the one command everything else
   points at:
   ```elixir
   precommit: [
     "deps.unlock --check-unused",
     # The audits read mix.lock only; they MUST precede compile — see below.
     "hex.audit",
     "deps.audit",
     "compile --warnings-as-errors",
     "format",
     "credo --strict",
     "usage_rules.sync --yes",
     "xref graph --label compile-connected --fail-above 0",
     "sobelow --exit --skip",         # Phoenix only — omit otherwise
     "docs --warnings-as-errors",
     "test --warnings-as-errors"
   ]
   ```
   Two hazards, both verified — preserve this ordering:
   - `mix compile` drops the Hex archive from the code path for the rest of the
     alias, so a `hex.audit` placed **after** it fails with `The task
     "hex.audit" could not be found`. Keep the audits above `compile`.
   - `usage_rules.sync` is Igniter-backed and **prompts for confirmation**,
     which hangs a non-interactive shell. Never run it bare — use `--yes` to
     fix in place or `--check` to fail without writing.

   Phoenix already has `aliases/0`, a shorter `precommit`, and `cli/0` with
   `preferred_envs: [precommit: :test]` — **extend those in place; never add a
   second alias.** For non-Phoenix projects, add `cli/0` yourself:
   ```elixir
   def cli do
     [preferred_envs: [precommit: :test]]
   end
   ```
   Leave `dialyzer` out of `precommit` — too slow for an edit loop, and CI runs
   it in its own job.
4. `mix deps.get`, then `mix credo.gen.config`.
5. Append `/priv/plts/` to `.gitignore`.
6. If the project does **not** use Ecto + Postgres, delete the `services:`
   block and `postgres` comment reference from the CI file(s) you kept.
7. Run `mix precommit`. **A stock `phx.new` app fails it in exactly two known
   places** (verified against phx.new 1.8.9). Fix both properly — do not
   suppress, baseline, or drop the check:

   - `mix credo --strict` exits 2 with three `Design.AliasUsage` findings on
     fully-qualified calls in generated files. Add `alias Phoenix.HTML.Form` to
     `lib/*_web/components/core_components.ex` and
     `alias Ecto.Adapters.SQL.Sandbox` to `test/support/data_case.ex`, then use
     the short names at the call sites. That clears all three.
   - `mix sobelow --exit --skip` exits 1 with `Config.CSP: Missing
     Content-Security-Policy`. Add a CSP to the `:browser` pipeline in
     `router.ex`:
     ```elixir
     plug :put_secure_browser_headers, %{
       "content-security-policy" =>
         "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:"
     }
     ```
     Tell the user this baseline covers LiveView's socket and Tailwind's
     injected styles, and that any CDN or external asset needs adding.

   Anything else `precommit` flags: fix trivial nits, and report the rest to
   the user rather than weakening the check. If `xref graph --label
   compile-connected` fails on freshly generated code, report it — it passes on
   a stock app, so a failure means something in the merge went wrong.

## 9b. Settle the CI provider

The template ships **both** `.github/workflows/ci.yml` and
`.forgejo/workflows/ci.yml`. Delete whichever the round-2 forge answer didn't
ask for, along with its PR template and dependency-bot config:

| Keep | Delete |
| --- | --- |
| GitHub only | `.forgejo/`, `renovate.json` |
| Forgejo only | `.github/`, and say `dependabot.yml` went with it |
| Both | nothing |

`renovate.json` is the Forgejo-side answer to Dependabot, which has no Forgejo
equivalent. **Tell the user it does nothing until Renovate is actually enabled
on their instance** — it is inert config, not a running bot.

### If you emitted a Forgejo workflow

Everything below is already baked into the shipped `.forgejo/workflows/ci.yml`.
Do not "improve" it back toward GitHub semantics — each difference is
load-bearing, and two of them cost real CI cycles to rediscover.

**Probe the runner before changing anything.** Its labels decide whether
`erlef/setup-beam` is usable at all:

```
GET /api/v1/repos/{owner}/{repo}/actions/runners   → .runners[].labels
```

- A real `ubuntu-22.04` / `ubuntu-24.04` label exists → you *may* switch to
  `erlef/setup-beam` with that label as `runs-on` and no `container:`.
- Only `docker` and/or `ubuntu-latest` → **setup-beam cannot work.** Keep the
  manual install. This is the default assumption, and the shipped workflow is
  written for it, so the do-nothing path is correct.

**Why setup-beam fails, so you don't try to patch it from the workflow.**
setup-beam picks its prebuilt tarball by looking up `$ImageOS`. The runner
embeds `act`, which injects that variable from the job's label
(`pkg/runner/run_context.go`):

```go
if platformName == "ubuntu-latest" {
    env["ImageOS"] = "ubuntu20"        // hardcoded
} else {
    platformName = strings.SplitN(strings.Replace(platformName, `-`, ``, 1), `.`, 2)[0]
    env["ImageOS"] = platformName      // "docker" -> "docker"
}
```

So `docker` → `"docker"`, which setup-beam's map rejects outright, and
`ubuntu-latest` → `"ubuntu20"`, which it maps to `ubuntu-20.04` with a
deprecation warning and then 404s, because builds.hex.pm publishes no
`ubuntu-20.04` artifacts for a modern OTP (verified: OTP 29 on ubuntu-20.04 is
a 404, on ubuntu-22.04 and 24.04 a 200). setup-beam has **no input** to
override the OS — only that env var, which you cannot win. Setting `ImageOS:`
at workflow or step level is a no-op. Do not try it, and do not try it twice.

**Do not "fix" this with a `hexpm/elixir` image either.** Those images have no
`node`, and the runner executes `checkout`/`cache` as JS actions inside the
container. You would trade one failure for another.
`ghcr.io/catthehacker/ubuntu:act-22.04` is the standard stand-in and has node,
git, curl, and unzip.

**The Ecto change the GitHub path doesn't need.** Forgejo jobs run *in* a
container, so services are reached by name rather than a mapped localhost port.
The workflow sets `DB_HOST: postgres`; make the app honour it:

```elixir
# config/test.exs
hostname: System.get_env("DB_HOST", "localhost"),
```

Apply that edit whenever you keep the Forgejo workflow **and** the project uses
Ecto. The default keeps local `mix test` working unchanged.

**Two things that are already handled, listed so you don't re-add them:** there
is no `permissions:` block (Forgejo ignores it and warns once per job — point
the user at Settings → Actions → Authorized Integrations), and actions are
referenced by full URL because Forgejo resolves bare `owner/repo` against the
instance's `DEFAULT_ACTIONS_URL`. Verify a tag exists before changing a pin:

```sh
git ls-remote --tags https://code.forgejo.org/actions/cache
```

**Known gap: actionlint cannot check the Forgejo workflow.** It rejects
full-URL `uses:` as malformed and doesn't recognise the `docker` label, and
neither is fixable with `actionlint.yaml`. Bare `actionlint` only scans
`.github/workflows/`, so the GitHub job stays green and the Forgejo file is
simply unlinted. If you edit it, re-check it by hand: `python3 -c "import
yaml;yaml.safe_load(open('.forgejo/workflows/ci.yml'))"` at minimum.

**Verify the install script without burning CI cycles.** It runs in the same
image CI uses:

```sh
docker run --rm --platform linux/amd64 \
  -v "$PWD/.tool-versions:/w/.tool-versions:ro" -w /w \
  -e BEAM_TARGET=ubuntu-22.04 ghcr.io/catthehacker/ubuntu:act-22.04 bash -c '...'
```

On Apple Silicon the BEAM will crash on **execution** under qemu with a
`user_drv` / `nouser` error. That is emulation, not your script — the VM booted
far enough to start the tty driver. Verify artifacts instead of running them:
`file` on `erts-*/bin/beam.smp` should say `x86-64`, and `ldd` should report no
missing libraries. There are no arm64 builds for `ubuntu-22.04` on
builds.hex.pm, so a native test isn't possible.

## 10. Merge the generator's AGENTS.md

Only applies when the generator produced one (`mix phx.new` does; `mix new`
does not). If it didn't, skip ahead.

The repo keeps **one** `AGENTS.md` — the template's — because two agent files
means one gets ignored. Read the generated file from the scratchpad and fold
it in:

1. **Framework prose** (its "Project guidelines", "Phoenix v1.8 guidelines",
   "JS and CSS guidelines", "UI/UX & design guidelines") goes under the
   template's existing **"Framework and library guidelines"** heading, above
   the paragraph explaining the usage-rules markers.
2. **The `<!-- usage-rules-start -->` … `<!-- usage-rules-end -->` block** is
   copied **verbatim, byte for byte, to the very bottom of `AGENTS.md`** —
   after the "Versions" section. Do not reformat, reflow, or edit anything
   between those markers; it is regenerated by `mix usage_rules.sync` and CI
   fails when it drifts.
3. **Reconcile duplicates in favour of the template.** Its "Use `mix precommit`
   when you are done" is already covered by the Commands table and Conventions
   — drop the duplicate. Keep genuinely new advice (e.g. "use `:req` for HTTP").
4. Run `mix usage_rules.sync --yes`, then `mix usage_rules.sync --check` to
   confirm it settles (exit 0). The first sync may rewrite the block — that's
   expected; commit the synced version, which is what CI compares against.
   Never run the task without `--yes` or `--check`: it prompts and will hang.

Then add what the interview surfaced, so the next agent inherits the decisions
rather than rediscovering them:

- A **Background jobs** subsection if Oban is in: that `testing: :manual` is
  set, so tests assert with `assert_enqueued/1` rather than expecting jobs to
  run, and which queues exist.
- A **Clustering** subsection if any multi-node option was chosen: which
  discovery mechanism, whether Horde is in play and what is allowed to depend
  on it, that `mix test` excludes `:distributed` and `mix test.distributed`
  runs them, and the eventual-consistency caveat if Horde is present.
- A line under Commands for `mix tidewave` if this is a non-Phoenix project.

## 11. Update the docs

- `AGENTS.md`: delete the "About this repo" template paragraph; write "Project
  overview" from the user's step-2 answer — their framing of what the thing is
  for, plus anything non-obvious about its architecture that the interview
  revealed. Trim Commands rows for tooling this project didn't install.
- `README.md`: rewrite for the actual project — name, the one-line description
  from step 2, how to run it, how to run the tests, `mix precommit`, and a
  short "Agent tooling" note covering Tidewave (start the server, then the MCP
  is live). Drop all template-bootstrap content, including "Optional extras" —
  mention those to the user instead and let them decide.

## 12. Finish

Summarize: the generator command used, files merged, capabilities scaffolded
(Oban / clustering / auth), Tidewave wiring and how to verify it, QA tooling
added, how `AGENTS.md` was merged, and the `mix precommit` result. Offer to
commit — do not commit unless the user agrees.
