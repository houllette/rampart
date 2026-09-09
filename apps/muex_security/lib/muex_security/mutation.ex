defmodule MuexSecurity.Mutation do
  @moduledoc false

  @spec build(module(), Macro.t(), String.t(), map(), keyword()) :: Muex.Mutator.mutation()
  def build(mutator, ast, description, context, metadata) do
    %{
      ast: ast,
      mutator: mutator,
      description: "#{mutator.name()}: #{description}",
      location: %{
        file: Map.get(context, :file, "unknown"),
        line: Keyword.get(metadata, :line, Map.get(context, :line, 0)) || 0
      }
    }
  end
end
