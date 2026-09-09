defmodule RampartSAST.Rules.UnsafeAtom do
  @moduledoc "Detects dynamic calls that can create atoms outside the garbage-collected heap."

  @behaviour RampartSAST.Rule

  alias RampartSAST.{AST, Match, Source}
  alias RampartSAST.Rule.Descriptor

  @impl true
  @spec descriptor() :: Descriptor.t()
  def descriptor do
    Descriptor.new!(
      id: "sast.unsafe-atom.v1",
      schema_version: 1,
      title: "Dynamic atom creation",
      description:
        "Finds syntactically dynamic inputs to APIs that can create atoms; attacker control is not inferred.",
      category: :atom_exhaustion,
      severity: :high,
      confidence: :low,
      scope: :source,
      tags: [:beam, :denial_of_service, :sink]
    )
  end

  @impl true
  @spec run_source(Source.t(), RampartSAST.Context.t(), keyword()) :: [Match.t()]
  def run_source(%Source{} = source, _context, _options) do
    source
    |> AST.calls()
    |> Enum.filter(&unsafe_dynamic_call?/1)
    |> Enum.map(&to_match(source, &1))
  end

  defp unsafe_dynamic_call?(%AST.Call{arguments: [input | _rest]} = call) do
    unsafe_call?(call) and not AST.literal?(input)
  end

  defp unsafe_dynamic_call?(_call), do: false

  defp unsafe_call?(%AST.Call{module: {:alias, "String"}, function: :to_atom, arguments: [_]}),
    do: true

  defp unsafe_call?(%AST.Call{module: {:alias, "List"}, function: :to_atom, arguments: [_]}),
    do: true

  defp unsafe_call?(%AST.Call{
         module: {:alias, "Module"},
         function: :concat,
         arguments: arguments
       })
       when length(arguments) in [1, 2],
       do: true

  defp unsafe_call?(%AST.Call{module: {:atom, :erlang}, function: :list_to_atom, arguments: [_]}),
    do: true

  defp unsafe_call?(%AST.Call{
         module: {:atom, :erlang},
         function: :binary_to_atom,
         arguments: [_, _]
       }),
       do: true

  defp unsafe_call?(_call), do: false

  defp to_match(source, call) do
    name = AST.call_name(call)

    Match.from_ast(source, call.ast,
      message: "dynamic input reaches atom-creating API #{name}",
      facts: %{
        api: name,
        argument_position: 1,
        input_shape: :dynamic,
        piped: call.piped?,
        suggested_family: :existing_atom
      }
    )
  end
end
