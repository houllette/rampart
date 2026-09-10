defmodule RampartEvaluation.Provider do
  @moduledoc false
  @behaviour RampartIAST.ContextProvider

  @candidate_key {__MODULE__, :candidate}

  @spec install_candidate!(RampartIAST.StaticCandidate.t()) :: :ok
  def install_candidate!(%RampartIAST.StaticCandidate{} = candidate) do
    :persistent_term.put(@candidate_key, RampartIAST.StaticCandidate.validate!(candidate))
  end

  @spec clear() :: :ok
  def clear do
    :persistent_term.erase(@candidate_key)
    :ok
  end

  @impl true
  def context, do: :library

  @impl true
  def sources do
    [
      RampartIAST.Source.new!(
        id: "evaluation.callback-argument.v1",
        schema_version: 1,
        context: :library,
        category: :untrusted_input,
        extraction: %{type: :callback_argument, position: 1},
        boundary: :in_process,
        provenance: %{origin: :evaluation_fixture}
      )
    ]
  end

  @impl true
  def sinks do
    [
      sink(
        "evaluation.command.v1",
        {System, :cmd, 2},
        [2],
        :command_execution_boundary,
        "System.cmd argument vector reaches an external process boundary",
        %{package: "elixir", package_version: System.version()}
      ),
      sink(
        "evaluation.deserialize.v1",
        {:erlang, :binary_to_term, 2},
        [1],
        :unsafe_deserialization_boundary,
        "binary_to_term decodes an external term",
        %{package: "erts", package_version: List.to_string(:erlang.system_info(:version))}
      ),
      sink(
        "evaluation.file-write.v1",
        {File, :write!, 2},
        [2],
        :filesystem_write_content_boundary,
        "File.write! content crosses a filesystem write boundary",
        %{package: "elixir", package_version: System.version()}
      ),
      sink(
        "evaluation.plug-send-resp.v1",
        {Plug.Conn, :send_resp, 3},
        [3],
        :http_response_body_boundary,
        "Plug response body crosses the HTTP response boundary",
        %{package: "plug", package_version: application_version!(:plug)}
      ),
      sink(
        "evaluation.overhead-observer.v1",
        {RampartEvaluation.Overhead.Sink, :observe, 1},
        [1],
        :evaluation_observation_boundary,
        "A side-effect-free local boundary measures targeted trace overhead",
        %{package: "rampart_evaluation", package_version: "1"}
      )
    ]
  end

  @impl true
  def candidates do
    [:persistent_term.get(@candidate_key)]
  end

  defp application_version!(application) do
    case Application.spec(application, :vsn) do
      nil -> raise "evaluation provider requires #{application} to be loaded"
      version -> to_string(version)
    end
  end

  defp sink(id, mfa, argument_positions, category, rationale, package) do
    RampartIAST.Sink.new!(
      id: id,
      schema_version: 1,
      context: :library,
      mfa: mfa,
      argument_positions: argument_positions,
      category: category,
      sanitizer_expectations: ["replace attacker-controlled value before the sink"],
      severity: :medium,
      rationale: rationale,
      provenance: Map.merge(%{origin: :reviewed_evaluation_provider}, package)
    )
  end
end
