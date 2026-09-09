defmodule Mix.Tasks.Havoc.Replay do
  use Mix.Task

  @shortdoc "Runs ExUnit with Havoc properties in deterministic corpus-only mode"

  @moduledoc """
  Runs the consumer's test suite with random Havoc generation disabled. Every
  `security_property` still replays all persisted concrete counterexamples.

      MIX_ENV=test mix havoc.replay

  Arguments are forwarded to `mix test`, so paths, line numbers, and ExUnit
  filters remain available.
  """

  @impl Mix.Task
  def run(args) do
    System.put_env("HAVOC_MODE", "corpus_only")
    Mix.Task.run("test", args)
  end
end
