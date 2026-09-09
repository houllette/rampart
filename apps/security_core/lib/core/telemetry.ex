defmodule Core.Telemetry do
  @moduledoc "Shared `:telemetry.span/3` naming and discrete suite events."

  defmodule Span do
    @moduledoc "Opaque token for spans that cross lazy enumerable continuations."

    @type t :: %__MODULE__{
            tool: atom(),
            stage: atom(),
            started_at: integer(),
            context: reference(),
            metadata: map()
          }

    @enforce_keys [:tool, :stage, :started_at, :context, :metadata]
    defstruct [:tool, :stage, :started_at, :context, :metadata]
  end

  @doc "Runs a conventional suite telemetry span."
  @spec span(tool :: atom(), stage :: atom(), metadata :: map(), (-> {result, map()})) :: result
        when result: term()
  def span(tool, stage, metadata, span_fun)
      when is_atom(tool) and is_atom(stage) and is_map(metadata) and is_function(span_fun, 0) do
    :telemetry.span([:core, tool, stage], metadata, span_fun)
  end

  @doc "Starts a conventional span that will be completed explicitly."
  @spec start_span(tool :: atom(), stage :: atom(), metadata :: map()) :: Span.t()
  def start_span(tool, stage, metadata)
      when is_atom(tool) and is_atom(stage) and is_map(metadata) do
    started_at = System.monotonic_time()
    context = make_ref()
    metadata = Map.put(metadata, :telemetry_span_context, context)

    :telemetry.execute(
      [:core, tool, stage, :start],
      %{monotonic_time: started_at, system_time: System.system_time()},
      metadata
    )

    %Span{
      tool: tool,
      stage: stage,
      started_at: started_at,
      context: context,
      metadata: metadata
    }
  end

  @doc "Stops a span started with `start_span/3`."
  @spec stop_span(Span.t(), metadata :: map(), measurements :: map()) :: :ok
  def stop_span(%Span{} = span, metadata, measurements \\ %{})
      when is_map(metadata) and is_map(measurements) do
    stopped_at = System.monotonic_time()

    measurements =
      Map.merge(measurements, %{
        duration: stopped_at - span.started_at,
        monotonic_time: stopped_at
      })

    metadata =
      span.metadata
      |> Map.merge(metadata)
      |> Map.put(:telemetry_span_context, span.context)

    :telemetry.execute([:core, span.tool, span.stage, :stop], measurements, metadata)
  end

  @doc "Completes a manually managed span with the conventional exception event."
  @spec exception_span(
          Span.t(),
          kind :: :error | :exit | :throw,
          reason :: term(),
          stacktrace :: list(),
          metadata :: map()
        ) :: :ok
  def exception_span(%Span{} = span, kind, reason, stacktrace, metadata \\ %{})
      when is_map(metadata) do
    stopped_at = System.monotonic_time()

    metadata =
      span.metadata
      |> Map.merge(metadata)
      |> Map.merge(%{kind: kind, reason: reason, stacktrace: stacktrace})
      |> Map.put(:telemetry_span_context, span.context)

    :telemetry.execute(
      [:core, span.tool, span.stage, :exception],
      %{duration: stopped_at - span.started_at, monotonic_time: stopped_at},
      metadata
    )
  end

  @doc "Emits the normalized per-finding event."
  @spec finding(tool :: atom(), Core.Finding.t()) :: :ok
  def finding(tool, %Core.Finding{} = finding) when is_atom(tool) do
    :telemetry.execute([:core, tool, :finding], %{}, %{finding: finding})
  end

  @doc "Emits an audit event immediately before an authorized binary launch."
  @spec launch(tool :: atom(), target :: term()) :: :ok
  def launch(tool, target) when is_atom(tool) do
    :telemetry.execute([:core, tool, :launch], %{}, %{target: target})
  end
end
