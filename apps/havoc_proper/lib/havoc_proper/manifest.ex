defmodule HavocProper.Manifest do
  @moduledoc """
  Builds a deterministic identity for one guided-search configuration.

  PropEr does not expose a portable initial RNG seed through the locked public
  API. The manifest therefore identifies the executable search configuration;
  exact generated inputs and counterexamples must still be retained separately.
  """

  @schema_version 1

  @doc "Builds the manifest and its deterministic run identity."
  @spec build(map(), map()) :: map()
  def build(config, guided) when is_map(config) and is_map(guided) do
    body = %{
      "schema_version" => @schema_version,
      "property" => %{
        "id" => config.property_id,
        "name" => config.property_name,
        "module" => inspect(config.module)
      },
      "search" => %{
        "backend" => "proper_targeted",
        "steps" => guided.search_steps,
        "strategy" => Atom.to_string(guided.search_strategy),
        "feedback_id" => guided.feedback_id,
        "feature_feedback" => not is_nil(guided.features),
        "coverage_seed_limit" => guided.max_coverage_seeds,
        "persist_coverage" => guided.persist_coverage
      },
      "coverage_modules" => Enum.map(guided.coverage_modules, &module_identity!/1),
      "runtime" => %{
        "elixir" => System.version(),
        "otp_release" => List.to_string(:erlang.system_info(:otp_release)),
        "proper" => application_version(:proper),
        "propcheck" => application_version(:propcheck)
      },
      "replay_note" =>
        "configuration identity only; retain exact candidate inputs because PropEr's public API does not expose a portable initial RNG seed"
    }

    Map.put(body, "run_id", identity(body))
  end

  @doc "Writes a manifest atomically as JSON."
  @spec write!(Path.t(), map()) :: :ok
  def write!(path, manifest) when is_binary(path) and is_map(manifest) do
    directory = Path.dirname(path)
    File.mkdir_p!(directory)
    temporary = path <> ".tmp-#{System.unique_integer([:positive])}"

    try do
      File.write!(temporary, JSON.encode!(manifest) <> "\n", [:binary, :sync])
      File.rename!(temporary, path)
    after
      File.rm(temporary)
    end

    :ok
  end

  defp module_identity!(module) do
    case :code.which(module) do
      path when is_list(path) ->
        binary = File.read!(List.to_string(path))

        %{
          "module" => inspect(module),
          "beam_sha256" => sha256(binary)
        }

      other ->
        raise ArgumentError,
              "coverage module has no BEAM file: #{inspect(module)} (#{inspect(other)})"
    end
  end

  defp application_version(application) do
    case Application.spec(application, :vsn) do
      nil -> "unknown"
      version when is_list(version) -> List.to_string(version)
      version -> to_string(version)
    end
  end

  defp identity(body) do
    body
    |> :erlang.term_to_binary([:deterministic])
    |> sha256()
  end

  defp sha256(binary),
    do: binary |> then(&:crypto.hash(:sha256, &1)) |> Base.encode16(case: :lower)
end
