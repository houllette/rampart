defmodule RampartSAST.Context do
  @moduledoc """
  Namespaced project and per-source facts produced by explicit context providers.

  Framework assumptions stay in provider namespaces instead of leaking into the
  scanner or unrelated rules.
  """

  @type t :: %__MODULE__{
          project: %{optional(String.t()) => map()},
          sources: %{optional(String.t()) => %{optional(Path.t()) => map()}}
        }

  defstruct project: %{}, sources: %{}

  @doc "Returns project facts for one versioned provider ID."
  @spec project_facts(context :: t(), provider_id :: String.t()) :: map()
  def project_facts(%__MODULE__{} = context, provider_id) when is_binary(provider_id) do
    Map.get(context.project, provider_id, %{})
  end

  @doc "Returns source facts for one provider ID and repository-relative path."
  @spec source_facts(context :: t(), provider_id :: String.t(), path :: Path.t()) :: map()
  def source_facts(%__MODULE__{} = context, provider_id, path)
      when is_binary(provider_id) and is_binary(path) do
    context.sources
    |> Map.get(provider_id, %{})
    |> Map.get(path, %{})
  end

  @doc false
  @spec put(t(), provider_id :: String.t(), contribution :: map()) :: t()
  def put(%__MODULE__{} = context, provider_id, %{project: project, sources: sources})
      when is_binary(provider_id) and is_map(project) and is_map(sources) do
    %__MODULE__{
      project: Map.put(context.project, provider_id, project),
      sources: Map.put(context.sources, provider_id, sources)
    }
  end
end
