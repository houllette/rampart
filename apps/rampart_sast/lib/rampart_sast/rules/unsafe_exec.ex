defmodule RampartSAST.Rules.UnsafeExec do
  @moduledoc "Detects APIs that hand a command string to a shell or port parser."

  @behaviour RampartSAST.Rule

  alias RampartSAST.{AST, Match, Source}
  alias RampartSAST.Rule.Descriptor

  @impl true
  @spec descriptor() :: Descriptor.t()
  def descriptor do
    Descriptor.new!(
      id: "sast.unsafe-exec.v1",
      schema_version: 1,
      title: "Shell-parsed command execution",
      description:
        "Finds shell-parsed command APIs while distinguishing them from argument-vector APIs such as System.cmd/3.",
      category: :command_execution,
      severity: :critical,
      confidence: :low,
      scope: :source,
      tags: [:beam, :command_injection, :sink]
    )
  end

  @impl true
  @spec run_source(Source.t(), RampartSAST.Context.t(), keyword()) :: [Match.t()]
  def run_source(%Source{} = source, _context, _options) do
    source
    |> AST.calls()
    |> Enum.flat_map(&match_call(source, &1))
  end

  defp match_call(source, %AST.Call{module: {:atom, :os}, function: :cmd} = call)
       when length(call.arguments) in [1, 2] do
    [command | _rest] = call.arguments
    [to_match(source, call, command)]
  end

  defp match_call(source, %AST.Call{module: {:alias, "System"}, function: :shell} = call)
       when length(call.arguments) in [1, 2] do
    [command | _rest] = call.arguments
    [to_match(source, call, command)]
  end

  defp match_call(
         source,
         %AST.Call{
           module: {:atom, :erlang},
           function: :open_port,
           arguments: [{:spawn, command}, _options]
         } = call
       ) do
    [to_match(source, call, command)]
  end

  defp match_call(_source, _call), do: []

  defp to_match(source, call, command) do
    name = AST.call_name(call)
    shape = if AST.literal?(command), do: :literal, else: :dynamic
    confidence = if shape == :dynamic, do: :medium, else: :low

    Match.from_ast(source, call.ast,
      message: "#{name} delegates command parsing to a shell-like interface",
      confidence: confidence,
      facts: %{
        api: name,
        argument_position: 1,
        command_shape: shape,
        piped: call.piped?,
        exploitability: :not_evaluated
      }
    )
  end
end
