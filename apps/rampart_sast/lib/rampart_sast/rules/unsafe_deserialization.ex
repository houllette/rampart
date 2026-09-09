defmodule RampartSAST.Rules.UnsafeDeserialization do
  @moduledoc "Detects Erlang term deserialization boundaries for explicit review."

  @behaviour RampartSAST.Rule

  alias RampartSAST.{AST, Match, Source}
  alias RampartSAST.Rule.Descriptor

  @impl true
  @spec descriptor() :: Descriptor.t()
  def descriptor do
    Descriptor.new!(
      id: "sast.binary-to-term.v1",
      schema_version: 1,
      title: "Erlang term deserialization boundary",
      description:
        "Finds binary_to_term calls and records use of the :safe option without treating it as untrusted-input proof.",
      category: :unsafe_deserialization,
      severity: :high,
      confidence: :low,
      scope: :source,
      tags: [:beam, :deserialization, :sink]
    )
  end

  @impl true
  @spec run_source(Source.t(), RampartSAST.Context.t(), keyword()) :: [Match.t()]
  def run_source(%Source{} = source, _context, _options) do
    source
    |> AST.calls()
    |> Enum.filter(&binary_to_term?/1)
    |> Enum.map(&to_match(source, &1))
  end

  defp binary_to_term?(%AST.Call{
         module: {:atom, :erlang},
         function: :binary_to_term,
         arguments: arguments
       })
       when length(arguments) in [1, 2],
       do: true

  defp binary_to_term?(_call), do: false

  defp to_match(source, call) do
    [binary | rest] = call.arguments
    safe_option? = safe_option?(rest)
    shape = if AST.literal?(binary), do: :literal, else: :dynamic

    Match.from_ast(source, call.ast,
      message: ":erlang.binary_to_term/#{length(call.arguments)} deserializes an Erlang term",
      confidence: if(shape == :dynamic, do: :medium, else: :low),
      facts: %{
        api: ":erlang.binary_to_term/#{length(call.arguments)}",
        argument_position: 1,
        input_shape: shape,
        safe_option: safe_option?,
        safe_option_effect: :limits_atom_creation_but_does_not_prove_trusted_input,
        piped: call.piped?
      }
    )
  end

  defp safe_option?([[safe]]) when safe == :safe, do: true
  defp safe_option?([options]) when is_list(options), do: :safe in options
  defp safe_option?(_arguments), do: false
end
