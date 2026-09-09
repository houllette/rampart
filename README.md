# Portico

An Elixir-native library that orchestrates a two-tier port-scanning pipeline —
fast discovery (RustScan) feeding deep enrichment (nmap) — with real
end-to-end backpressure, bounded concurrency, cancellation, and typed
structured results. It's designed as an embeddable dependency with pluggable
scanner engines behind clean behaviours, so it folds into higher-level
security scanning infrastructure rather than being operated as a CLI.

## Installation

Add `portico` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:portico, "~> 0.1.0"}
  ]
end
```

## Development

```sh
mix deps.get
mix test
mix precommit   # runs the same checks CI runs
```

### Agent tooling

This repo ships a [Tidewave](https://tidewave.ai) MCP server for dev-time
introspection (evaluate code in the running app, read logs, query state).
Start it with:

```sh
mix tidewave
```

Then confirm the connection with `/mcp` in Claude Code. The `.mcp.json` in
this repo is pending approval the first time you open the project in an
interactive `claude` session.
