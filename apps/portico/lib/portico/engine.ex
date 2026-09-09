defmodule Portico.Engine do
  @moduledoc "Resolves built-in and application-registered scanner engines."

  @built_ins %{
    discovery: %{rustscan: Portico.Discovery.RustScan},
    enrichment: %{nmap: Portico.Enrichment.Nmap}
  }

  @type stage :: :discovery | :enrichment

  @doc "Resolves an engine alias or validates an engine module."
  @spec resolve!(stage(), atom()) :: module()
  def resolve!(stage, engine) when stage in [:discovery, :enrichment] and is_atom(engine) do
    module =
      get_in(@built_ins, [stage, engine]) ||
        get_in(Application.get_env(:portico, :engines, %{}), [stage, engine]) ||
        engine

    ensure_engine!(stage, module)
  end

  @doc "Validates engine-specific options using its declared schema."
  @spec validate_options!(module(), keyword()) :: keyword()
  def validate_options!(engine, opts) do
    NimbleOptions.validate!(opts, engine.option_schema())
  end

  @doc "Returns the engine's static capabilities."
  @spec capabilities(stage(), atom()) :: map()
  def capabilities(stage, engine) do
    module = resolve!(stage, engine)
    if function_exported?(module, :capabilities, 0), do: module.capabilities(), else: %{}
  end

  defp ensure_engine!(stage, module) do
    required =
      case stage do
        :discovery -> [option_schema: 0, stream: 2]
        :enrichment -> [option_schema: 0, enrich: 2]
      end

    if Code.ensure_loaded?(module) and
         Enum.all?(required, fn {name, arity} -> function_exported?(module, name, arity) end) do
      module
    else
      raise ArgumentError, "#{inspect(module)} is not a valid #{stage} engine"
    end
  end
end
