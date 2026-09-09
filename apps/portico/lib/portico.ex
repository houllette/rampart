defmodule Portico do
  @moduledoc """
  Builds lazy, authorized discovery-to-enrichment scans.

  A scope policy is mandatory at enumeration time. Configure one globally with
  `config :portico, :scope, policy` or pass one explicitly:

      scope = Portico.Scope.Allowlist.new!(["10.0.0.0/24"])

      Portico.scan("10.0.0.0/24", scope: scope)
      |> Portico.discover(engine: :rustscan, ports: :full)
      |> Portico.enrich(engine: :nmap, max_concurrency: 4)
      |> Portico.stream()
      |> Stream.each(&persist/1)
      |> Stream.run()

  Nothing is executed until the returned stream is enumerated. Authorization is
  checked for every requested target before the discovery binary starts and
  again for every discovered host before enrichment starts.
  """

  alias Portico.{Engine, Scan, Scan.Stage, Target}

  @scan_schema [
    scope: [type: :any],
    audit: [type: :any, default: nil],
    metadata: [type: :map, default: %{}],
    scan_id: [type: :string]
  ]

  @doc "Creates an immutable scan plan without starting external processes."
  @spec scan(String.t() | Target.t() | [String.t() | Target.t()], keyword()) :: Scan.t()
  def scan(targets, opts \\ []) do
    default_scope = Application.get_env(:portico, :scope, Core.Scope.DenyAll)
    opts = NimbleOptions.validate!(opts, @scan_schema)

    %Scan{
      id: opts[:scan_id] || generate_scan_id(),
      targets: normalize_targets!(targets),
      scope: opts[:scope] || default_scope,
      audit: opts[:audit],
      metadata: opts[:metadata]
    }
  end

  @doc "Configures the discovery stage and validates engine-specific options."
  @spec discover(Scan.t(), keyword()) :: Scan.t()
  def discover(%Scan{} = scan, opts \\ []) do
    {engine_name, engine_opts} = Keyword.pop(opts, :engine, :rustscan)
    engine = Engine.resolve!(:discovery, engine_name)
    engine_opts = Engine.validate_options!(engine, engine_opts)
    %{scan | discovery: %Stage{engine: engine, opts: engine_opts}}
  end

  @doc "Configures bounded enrichment and validates nmap or custom-engine options."
  @spec enrich(Scan.t(), keyword()) :: Scan.t()
  def enrich(%Scan{} = scan, opts \\ []) do
    {engine_name, opts} = Keyword.pop(opts, :engine, :nmap)

    {pipeline_opts, engine_opts} =
      Keyword.split(opts, [:max_concurrency, :host_batch_size, :batch_timeout, :rate_limit])

    pipeline_opts = validate_pipeline_options!(pipeline_opts, scan)
    engine = Engine.resolve!(:enrichment, engine_name)
    engine_opts = Engine.validate_options!(engine, engine_opts)

    %{
      scan
      | enrichment: %Stage{engine: engine, opts: engine_opts},
        max_concurrency: pipeline_opts[:max_concurrency],
        host_batch_size: pipeline_opts[:host_batch_size],
        batch_timeout: pipeline_opts[:batch_timeout],
        rate_limit: pipeline_opts[:rate_limit]
    }
  end

  @doc "Returns a lazy stream of `%Portico.Host{}` results."
  @spec stream(Scan.t()) :: Enumerable.t(Portico.Host.t())
  def stream(%Scan{discovery: %Stage{}, enrichment: %Stage{}} = scan) do
    Portico.Stream.build(scan)
  end

  def stream(%Scan{}) do
    raise ArgumentError,
          "both discovery and enrichment stages must be configured before streaming"
  end

  @doc "Returns a lazy normalized-finding stream for cross-tool consumption."
  @spec findings(Scan.t()) :: Enumerable.t(Core.Finding.t())
  def findings(%Scan{} = scan) do
    scan
    |> stream()
    |> Stream.flat_map(&to_findings/1)
  end

  @doc "Observes a scan plan as a lazy stream of normalized findings."
  @spec observe(Scan.t()) :: Enumerable.t(Core.Finding.t())
  def observe(%Scan{} = scan), do: findings(scan)

  @doc "Returns Portico's versioned, machine-discoverable validation actions."
  @spec validation_actions() :: [Core.Validation.Action.t()]
  def validation_actions, do: Core.Validation.actions(Portico.Validator)

  @doc "Rechecks one Portico endpoint finding and returns proof, refutation, or uncertainty."
  @spec validate(Core.Finding.t(), keyword()) :: Core.Validation.Result.t()
  def validate(%Core.Finding{} = finding, opts \\ []) do
    request = Core.Validation.request(Portico.Validator.action(), finding)
    Core.Validation.run(Portico.Validator, request, opts)
  end

  @doc "Projects a native host result into one normalized Core finding per open port."
  @spec to_findings(Portico.Host.t()) :: [Core.Finding.t()]
  def to_findings(%Portico.Host{} = host), do: Portico.Finding.from_host(host)

  @doc "Returns the capability declaration for an engine."
  @spec capabilities(:discovery | :enrichment, atom()) :: map()
  def capabilities(stage, engine), do: Engine.capabilities(stage, engine)

  @doc false
  @spec validate_rate_limit(term()) :: {:ok, nil | map()} | {:error, String.t()}
  def validate_rate_limit(nil), do: {:ok, nil}

  def validate_rate_limit(opts) when is_list(opts) do
    schema = [
      allowed_messages: [type: :pos_integer, required: true],
      interval: [type: :pos_integer, required: true]
    ]

    case NimbleOptions.validate(opts, schema) do
      {:ok, validated} -> {:ok, Map.new(validated)}
      {:error, error} -> {:error, Exception.message(error)}
    end
  end

  def validate_rate_limit(_other), do: {:error, "expected nil or rate-limit keyword options"}

  defp validate_pipeline_options!(opts, scan) do
    schema = [
      max_concurrency: [type: :pos_integer, default: scan.max_concurrency],
      host_batch_size: [type: :pos_integer, default: scan.host_batch_size],
      batch_timeout: [type: :pos_integer, default: scan.batch_timeout],
      rate_limit: [
        type: {:custom, __MODULE__, :validate_rate_limit, []},
        default: scan.rate_limit
      ]
    ]

    NimbleOptions.validate!(opts, schema)
  end

  defp normalize_targets!(targets) when is_list(targets) and targets != [] do
    Enum.map(targets, &normalize_target!/1)
  end

  defp normalize_targets!([]), do: raise(ArgumentError, "at least one target is required")
  defp normalize_targets!(target), do: [normalize_target!(target)]

  defp normalize_target!(%Target{} = target), do: target
  defp normalize_target!(target) when is_binary(target), do: Target.parse!(target)

  defp normalize_target!(target),
    do: raise(ArgumentError, "invalid scan target: #{inspect(target)}")

  defp generate_scan_id do
    "scan-#{System.system_time(:millisecond)}-#{System.unique_integer([:positive, :monotonic])}"
  end
end
