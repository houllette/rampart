defmodule Foray.Engine do
  @moduledoc "Resolves built-in and application-registered fuzzing engines."

  @built_ins %{ffuf: Foray.Fuzz.Ffuf}

  @doc "Resolves an engine alias or validates an engine module."
  @spec resolve!(atom()) :: module()
  def resolve!(engine) when is_atom(engine) do
    module =
      Map.get(@built_ins, engine) ||
        Map.get(Application.get_env(:foray, :engines, %{}), engine) ||
        engine

    if Code.ensure_loaded?(module) and function_exported?(module, :option_schema, 0) and
         function_exported?(module, :stream, 2) do
      module
    else
      raise ArgumentError, "#{inspect(module)} is not a valid Foray fuzz engine"
    end
  end

  @doc "Validates engine-specific options."
  @spec validate_options!(module(), keyword()) :: keyword()
  def validate_options!(engine, opts), do: NimbleOptions.validate!(opts, engine.option_schema())

  @doc "Returns an engine's static capability declaration."
  @spec capabilities(atom()) :: [atom()]
  def capabilities(engine) do
    module = resolve!(engine)
    if function_exported?(module, :capabilities, 0), do: module.capabilities(), else: []
  end
end
