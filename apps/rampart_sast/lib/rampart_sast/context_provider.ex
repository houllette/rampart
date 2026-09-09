defmodule RampartSAST.ContextProvider do
  @moduledoc """
  Behaviour for framework or ecosystem context extraction.

  Providers receive already parsed sources and return plain namespaced facts.
  They are selected as modules by the current host; source text never selects
  executable provider code.
  """

  alias RampartSAST.{Context, Diagnostic, Source}

  @type specification :: module() | {module(), keyword()}
  @type contribution :: %{
          required(:project) => map(),
          required(:sources) => %{optional(Path.t()) => map()}
        }

  @callback id() :: String.t()
  @callback build([Source.t()], keyword()) :: {:ok, contribution()} | {:error, String.t()}

  @doc "Builds namespaced context and diagnostics from host-selected providers."
  @spec build([Source.t()], [specification()], timeout_ms :: pos_integer()) ::
          {Context.t(), [Diagnostic.t()]}
  def build(sources, specifications, timeout_ms \\ 5_000)
      when is_list(sources) and is_list(specifications) and is_integer(timeout_ms) and
             timeout_ms > 0 do
    specifications
    |> Enum.map(&resolve!/1)
    |> ensure_unique_ids!()
    |> Enum.reduce({%Context{}, []}, fn provider, {context, diagnostics} ->
      run_provider(provider, sources, timeout_ms, context, diagnostics)
    end)
  end

  defp resolve!(module) when is_atom(module), do: resolve!({module, []})

  defp resolve!({module, options}) when is_atom(module) and is_list(options) do
    valid? =
      Code.ensure_loaded?(module) and function_exported?(module, :id, 0) and
        function_exported?(module, :build, 2)

    unless valid?, do: raise(ArgumentError, "#{inspect(module)} is not a SAST context provider")

    id = module.id()

    unless versioned_id?(id),
      do: raise(ArgumentError, "SAST context provider IDs must be explicitly versioned")

    %{module: module, options: options, id: id}
  end

  defp resolve!(specification) do
    raise ArgumentError, "invalid SAST context provider specification: #{inspect(specification)}"
  end

  defp ensure_unique_ids!(providers) do
    if length(Enum.uniq_by(providers, & &1.id)) == length(providers) do
      Enum.sort_by(providers, & &1.id)
    else
      raise ArgumentError, "SAST context providers must expose unique IDs"
    end
  end

  defp run_provider(provider, sources, timeout_ms, context, diagnostics) do
    case safe_build(provider, sources, timeout_ms) do
      {:completed, {:ok, %{project: project, sources: source_facts} = contribution}}
      when is_map(project) and is_map(source_facts) ->
        if valid_source_facts?(source_facts, sources) do
          {Context.put(context, provider.id, contribution), diagnostics}
        else
          {context, [invalid_contribution(provider.id) | diagnostics]}
        end

      {:completed, {:error, message}} when is_binary(message) ->
        {context, [provider_failed(provider.id, message) | diagnostics]}

      {:completed, _invalid} ->
        {context, [invalid_contribution(provider.id) | diagnostics]}

      {:failed, message} ->
        {context, [provider_failed(provider.id, message) | diagnostics]}

      :timeout ->
        diagnostic =
          Diagnostic.new!(
            level: :error,
            phase: :context,
            code: :provider_timeout,
            rule_id: provider.id,
            message: "context provider exceeded #{timeout_ms} ms"
          )

        {context, [diagnostic | diagnostics]}
    end
  end

  defp safe_build(provider, sources, timeout_ms) do
    task = Task.async(fn -> invoke_provider(provider, sources) end)

    case Task.yield(task, timeout_ms) || Task.shutdown(task, :brutal_kill) do
      {:ok, result} -> {:completed, result}
      {:exit, reason} -> {:failed, "context provider exited: #{inspect(reason, limit: 20)}"}
      nil -> :timeout
    end
  end

  defp invoke_provider(provider, sources) do
    provider.module.build(sources, provider.options)
  rescue
    error -> {:error, "context provider failed: #{Exception.message(error)}"}
  catch
    kind, reason -> {:error, "context provider #{kind}: #{inspect(reason, limit: 20)}"}
  end

  defp provider_failed(provider_id, message) do
    Diagnostic.new!(
      level: :error,
      phase: :context,
      code: :provider_failed,
      rule_id: provider_id,
      message: message
    )
  end

  defp valid_source_facts?(source_facts, sources) do
    known_paths = MapSet.new(sources, & &1.path)

    Enum.all?(source_facts, fn {path, facts} ->
      is_binary(path) and MapSet.member?(known_paths, path) and is_map(facts)
    end)
  end

  defp invalid_contribution(provider_id) do
    Diagnostic.new!(
      level: :error,
      phase: :context,
      code: :invalid_provider_result,
      rule_id: provider_id,
      message: "context provider returned invalid or unknown source facts"
    )
  end

  defp versioned_id?(value) do
    is_binary(value) and Regex.match?(~r/^[a-z0-9][a-z0-9._-]*\.v[1-9][0-9]*$/, value)
  end
end
