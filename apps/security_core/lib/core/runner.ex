defmodule Core.Runner do
  @moduledoc """
  Shared, swappable external-process seam.

  `stream/2` emits bounded binary chunks (or backend-specific tagged stdout and
  stderr chunks). Parsing lines, JSON, XML, or records remains tool-owned.
  """

  @type argv :: [String.t()]

  @callback stream(argv(), keyword()) :: Enumerable.t()
  @callback run(argv(), keyword()) :: {binary(), exit_status :: integer()}

  @doc "Returns a lazy, backpressured process-output enumerable."
  @spec stream(argv(), keyword()) :: Enumerable.t()
  def stream(argv, opts \\ []) do
    {backend, backend_opts} = backend_and_opts(opts)
    backend.stream(argv, backend_opts)
  end

  @doc "Runs a short-lived command with bounded collection."
  @spec run(argv(), keyword()) :: {binary(), integer()}
  def run(argv, opts \\ []) do
    {backend, backend_opts} = backend_and_opts(opts)
    backend.run(argv, backend_opts)
  end

  @doc "Returns the configured backend module."
  @spec backend() :: module()
  def backend do
    Application.get_env(:security_core, :runner, Core.Runner.Exile)
  end

  defp backend_and_opts(opts) do
    Keyword.pop(opts, :backend, backend())
  end
end
