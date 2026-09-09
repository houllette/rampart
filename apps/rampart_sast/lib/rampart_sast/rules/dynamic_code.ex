defmodule RampartSAST.Rules.DynamicCode do
  @moduledoc "Detects runtime code and template evaluation boundaries."

  @behaviour RampartSAST.Rule

  alias RampartSAST.{AST, Match, Source}
  alias RampartSAST.Rule.Descriptor

  @code_functions [:eval_file, :eval_quoted, :eval_string]
  @eex_functions [:eval_file, :eval_string]

  @impl true
  @spec descriptor() :: Descriptor.t()
  def descriptor do
    Descriptor.new!(
      id: "sast.dynamic-code.v1",
      schema_version: 1,
      title: "Runtime code evaluation",
      description:
        "Finds Code and EEx evaluation APIs and records whether the evaluated input is syntactically literal.",
      category: :code_execution,
      severity: :critical,
      confidence: :low,
      scope: :source,
      tags: [:beam, :code_execution, :sink]
    )
  end

  @impl true
  @spec run_source(Source.t(), RampartSAST.Context.t(), keyword()) :: [Match.t()]
  def run_source(%Source{} = source, _context, _options) do
    source
    |> AST.calls()
    |> Enum.filter(&dynamic_code_call?/1)
    |> Enum.map(&to_match(source, &1))
  end

  defp dynamic_code_call?(%AST.Call{
         module: {:alias, "Code"},
         function: function,
         arguments: [_input | _rest]
       }) do
    function in @code_functions
  end

  defp dynamic_code_call?(%AST.Call{
         module: {:alias, "EEx"},
         function: function,
         arguments: [_input | _rest]
       }) do
    function in @eex_functions
  end

  defp dynamic_code_call?(_call), do: false

  defp to_match(source, call) do
    input = List.first(call.arguments)
    shape = if AST.literal?(input), do: :literal, else: :dynamic
    name = AST.call_name(call)

    Match.from_ast(source, call.ast,
      message: "#{name} evaluates source or template code at runtime",
      confidence: if(shape == :dynamic, do: :medium, else: :low),
      facts: %{
        api: name,
        argument_position: 1,
        input_shape: shape,
        piped: call.piped?,
        exploitability: :not_evaluated
      }
    )
  end
end
