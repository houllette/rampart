defmodule Foray do
  @moduledoc """
  Builds lazy, scope-safe web-fuzzing jobs that stream normalized Core findings.

  Foray orchestrates a small number of whole ffuf processes. It deliberately
  delegates request-level concurrency to ffuf rather than fanning individual
  payloads out into BEAM tasks.
  """

  alias Core.Seed
  alias Foray.{Engine, FuzzPoint, Oracle, Scan, Target, Wordlist}
  alias Foray.Scan.Engine, as: EngineConfig

  @target_schema [
    scope: [type: :any],
    audit: [type: :any, default: nil],
    metadata: [type: :map, default: %{}],
    scan_id: [type: :string],
    method: [type: :string, default: "GET"],
    headers: [type: :map, default: %{}],
    body: [type: {:or, [:string, nil]}, default: nil],
    cookies: [type: {:or, [:string, nil]}, default: nil],
    max_concurrency: [type: :pos_integer, default: 2],
    engine: [type: :atom, default: :ffuf],
    engine_options: [type: :keyword_list, default: []]
  ]

  @input_schema [
    wordlist: [type: :any, required: true],
    keyword: [type: :string, default: "FUZZ"],
    class: [type: :atom, default: :discovery]
  ]

  @doc "Creates a lazy multi-target fuzzing plan from URLs, targets, or `:target` Core seeds."
  @spec target(
          String.t()
          | Target.t()
          | Seed.t()
          | [String.t() | Target.t() | Seed.t()],
          keyword()
        ) :: Scan.t()
  def target(targets, opts \\ []) do
    opts = NimbleOptions.validate!(opts, @target_schema)
    engine = Engine.resolve!(opts[:engine])
    engine_opts = Engine.validate_options!(engine, opts[:engine_options])
    default_scope = Application.get_env(:foray, :scope, Core.Scope.DenyAll)

    %Scan{
      id: opts[:scan_id] || generate_scan_id(),
      targets: normalize_targets!(targets),
      scope: opts[:scope] || default_scope,
      audit: opts[:audit],
      metadata: opts[:metadata],
      method: normalize_method!(opts[:method]),
      headers: normalize_headers!(opts[:headers]),
      body: opts[:body],
      cookies: opts[:cookies],
      max_concurrency: opts[:max_concurrency],
      oracle: struct(Oracle),
      engine: struct(EngineConfig, module: engine, opts: engine_opts)
    }
  end

  @doc "Adds a path fuzz point by appending its keyword to every target path."
  @spec fuzz_path(Scan.t(), keyword()) :: Scan.t()
  def fuzz_path(%Scan{} = scan, opts) do
    opts = input_options!(opts)
    keyword = opts[:keyword]

    targets =
      Enum.map(scan.targets, fn target ->
        separator = if String.ends_with?(target.path, "/"), do: "", else: "/"
        Target.put_path(target, target.path <> separator <> keyword)
      end)

    scan
    |> Map.put(:targets, targets)
    |> add_input!(:url, nil, opts)
  end

  @doc "Adds a query-parameter fuzz point."
  @spec fuzz_param(Scan.t(), String.t(), keyword()) :: Scan.t()
  def fuzz_param(%Scan{} = scan, name, opts) when is_binary(name) do
    if String.trim(name) == "", do: raise(ArgumentError, "parameter name cannot be empty")
    opts = input_options!(opts)
    encoded_name = URI.encode_www_form(name)

    targets =
      Enum.map(scan.targets, fn target ->
        entry = encoded_name <> "=" <> opts[:keyword]
        query = if target.query in [nil, ""], do: entry, else: target.query <> "&" <> entry
        Target.put_query(target, query)
      end)

    scan
    |> Map.put(:targets, targets)
    |> add_input!(:query, name, opts)
  end

  @doc "Adds a header fuzz point. `Host` headers are categorized as virtual-host findings."
  @spec fuzz_header(Scan.t(), String.t(), keyword()) :: Scan.t()
  def fuzz_header(%Scan{} = scan, name, opts) when is_binary(name) do
    validate_header_name!(name)
    opts = input_options!(opts)

    scan
    |> Map.update!(:headers, &Map.put(&1, name, opts[:keyword]))
    |> add_input!(:header, name, opts)
  end

  @doc "Adds a cookie fuzz point."
  @spec fuzz_cookie(Scan.t(), String.t(), keyword()) :: Scan.t()
  def fuzz_cookie(%Scan{} = scan, name, opts) when is_binary(name) do
    if String.trim(name) == "", do: raise(ArgumentError, "cookie name cannot be empty")
    opts = input_options!(opts)
    cookie = "#{name}=#{opts[:keyword]}"
    cookies = if scan.cookies in [nil, ""], do: cookie, else: scan.cookies <> "; " <> cookie

    scan
    |> Map.put(:cookies, cookies)
    |> add_input!(:cookie, name, opts)
  end

  @doc "Sets a request-body template containing the configured fuzz keyword."
  @spec fuzz_body(Scan.t(), String.t(), keyword()) :: Scan.t()
  def fuzz_body(%Scan{} = scan, template, opts) when is_binary(template) do
    opts = input_options!(opts)

    unless String.contains?(template, opts[:keyword]) do
      raise ArgumentError, "body template must contain #{inspect(opts[:keyword])}"
    end

    scan
    |> Map.put(:body, template)
    |> add_input!(:body, nil, opts)
  end

  @doc "Merges first-class ffuf matcher criteria into the plan's oracle."
  @spec match(Scan.t(), keyword()) :: Scan.t()
  def match(%Scan{} = scan, opts) do
    {criteria, mode, auto?} = normalize_oracle_options!(opts, :matcher)

    oracle = %{
      scan.oracle
      | matchers: Map.merge(scan.oracle.matchers, criteria),
        matcher_mode: mode || scan.oracle.matcher_mode,
        auto_calibrate: scan.oracle.auto_calibrate or auto?
    }

    %{scan | oracle: oracle}
  end

  @doc "Merges first-class ffuf filter criteria into the plan's oracle."
  @spec filter(Scan.t(), keyword()) :: Scan.t()
  def filter(%Scan{} = scan, opts) do
    {criteria, mode, _auto?} = normalize_oracle_options!(opts, :filter)
    oracle = %{scan.oracle | filters: Map.merge(scan.oracle.filters, criteria)}
    %{scan | oracle: %{oracle | filter_mode: mode || oracle.filter_mode}}
  end

  @doc "Enables ffuf auto-calibration with optional repeated calibration strings."
  @spec auto_calibrate(Scan.t(), keyword()) :: Scan.t()
  def auto_calibrate(%Scan{} = scan, opts \\ []) do
    schema = [strings: [type: {:list, :string}, default: []]]
    opts = NimbleOptions.validate!(opts, schema)
    %{scan | oracle: %{scan.oracle | auto_calibrate: true, calibration_strings: opts[:strings]}}
  end

  @doc "Selects ffuf's multi-input mode."
  @spec mode(Scan.t(), :clusterbomb | :pitchfork | :sniper) :: Scan.t()
  def mode(%Scan{} = scan, mode) when mode in [:clusterbomb, :pitchfork, :sniper] do
    %{scan | mode: mode}
  end

  @doc "Configures the aggregate request ceiling and ffuf's intra-job workers."
  @spec rate(Scan.t(), keyword()) :: Scan.t()
  def rate(%Scan{} = scan, opts) do
    schema = [
      requests_per_second: [type: :pos_integer, default: scan.aggregate_rate],
      threads: [type: :pos_integer, default: scan.threads],
      max_jobs: [type: :pos_integer, default: scan.max_concurrency],
      delay: [type: {:or, [:string, nil]}, default: scan.delay],
      max_time: [type: :pos_integer, default: scan.max_time]
    ]

    opts = NimbleOptions.validate!(opts, schema)
    validate_delay!(opts[:delay])

    %{
      scan
      | aggregate_rate: opts[:requests_per_second],
        threads: opts[:threads],
        max_concurrency: opts[:max_jobs],
        delay: opts[:delay],
        max_time: opts[:max_time]
    }
  end

  @doc "Limits how quickly whole jobs may start; this is separate from the HTTP request ceiling."
  @spec job_rate_limit(Scan.t(), keyword()) :: Scan.t()
  def job_rate_limit(%Scan{} = scan, opts) do
    schema = [
      allowed_jobs: [type: :pos_integer, required: true],
      interval: [type: :pos_integer, required: true]
    ]

    opts = NimbleOptions.validate!(opts, schema)

    %{scan | job_rate_limit: %{allowed_messages: opts[:allowed_jobs], interval: opts[:interval]}}
  end

  @doc "Enables bounded ffuf-native recursion. Derived matches are rechecked before emission."
  @spec recurse(Scan.t(), keyword()) :: Scan.t()
  def recurse(%Scan{} = scan, opts \\ []) do
    schema = [
      depth: [type: :pos_integer, default: 1],
      strategy: [type: {:in, [:default, :greedy]}, default: :default]
    ]

    opts = NimbleOptions.validate!(opts, schema)
    %{scan | recursion: %{depth: opts[:depth], strategy: opts[:strategy]}}
  end

  @doc "Replaces the fuzz engine without changing orchestration."
  @spec engine(Scan.t(), atom(), keyword()) :: Scan.t()
  def engine(%Scan{} = scan, engine, opts \\ []) do
    module = Engine.resolve!(engine)
    config = struct(EngineConfig, module: module, opts: Engine.validate_options!(module, opts))
    %{scan | engine: config}
  end

  @doc "Returns a lazy, backpressured stream of normalized findings."
  @spec stream(Scan.t()) :: Enumerable.t(Core.Finding.t())
  def stream(%Scan{} = scan), do: Foray.Stream.new(scan)

  @doc "Observes a fuzzing plan as a lazy stream of normalized findings."
  @spec observe(Scan.t()) :: Enumerable.t(Core.Finding.t())
  def observe(%Scan{} = scan), do: stream(scan)

  @doc "Returns Foray's versioned, machine-discoverable validation actions."
  @spec validation_actions() :: [Core.Validation.Action.t()]
  def validation_actions, do: Core.Validation.actions(Foray.Validator)

  @doc "Replays one concrete finding through its originating scan plan."
  @spec validate(Core.Finding.t(), Scan.t()) :: Core.Validation.Result.t()
  def validate(%Core.Finding{} = finding, %Scan{} = scan) do
    request = Core.Validation.request(Foray.Validator.action(), finding)
    Core.Validation.run(Foray.Validator, request, scan: scan)
  end

  @doc "Returns the capability declaration for an engine."
  @spec capabilities(atom()) :: [atom()]
  def capabilities(engine), do: Engine.capabilities(engine)

  @doc "Promotes a finding-derived value into the shared corpus format."
  @spec promote(Core.Finding.t(), String.t(), keyword()) :: Seed.t()
  def promote(%Core.Finding{} = finding, value, opts \\ []) when is_binary(value) do
    schema = [classes: [type: {:list, :atom}, default: []], meta: [type: :map, default: %{}]]
    opts = NimbleOptions.validate!(opts, schema)

    %Seed{
      id: Core.Finding.dedupe_id(:foray, ["promoted_seed", finding.id, value]),
      value: value,
      classes: opts[:classes],
      provenance: :promoted_finding,
      origin: {finding.source, finding.id},
      meta: opts[:meta]
    }
  end

  defp input_options!(opts) do
    opts = NimbleOptions.validate!(opts, @input_schema)
    validate_keyword!(opts[:keyword])
    opts
  end

  defp add_input!(scan, location, name, opts) do
    wordlist = normalize_wordlist!(opts[:wordlist], opts[:keyword], opts[:class])
    scan = put_wordlist!(scan, wordlist)

    point = %FuzzPoint{
      keyword: opts[:keyword],
      location: location,
      name: name,
      wordlist_ref: wordlist.ref,
      classes: [opts[:class]]
    }

    %{scan | fuzz_points: scan.fuzz_points ++ [point]}
  end

  defp normalize_wordlist!(path, keyword, class) when is_binary(path) do
    if String.trim(path) == "", do: raise(ArgumentError, "wordlist path cannot be empty")
    %Wordlist{ref: "input:#{keyword}", keyword: keyword, source: {:file, path}, classes: [class]}
  end

  defp normalize_wordlist!(seeds, keyword, class) when is_list(seeds) and seeds != [] do
    unless Enum.all?(seeds, &match?(%Seed{value: value} when is_binary(value), &1)) do
      raise ArgumentError, "seed wordlists require non-empty Core.Seed values"
    end

    if Enum.any?(seeds, &String.contains?(&1.value, ["\n", "\r"])) do
      raise ArgumentError, "seed values cannot contain line separators"
    end

    %Wordlist{
      ref: "input:#{keyword}",
      keyword: keyword,
      source: {:seeds, seeds},
      classes: [class]
    }
  end

  defp normalize_wordlist!({:input_command, command, count}, keyword, class)
       when is_binary(command) and is_integer(count) and count > 0 do
    command_wordlist!(command, count, nil, keyword, class)
  end

  defp normalize_wordlist!({:input_command, command, count, shell}, keyword, class)
       when is_binary(command) and is_integer(count) and count > 0 and is_binary(shell) do
    command_wordlist!(command, count, shell, keyword, class)
  end

  defp normalize_wordlist!(source, _keyword, _class) do
    raise ArgumentError, "invalid wordlist source: #{inspect(source)}"
  end

  defp command_wordlist!(command, count, shell, keyword, class) do
    cond do
      String.trim(command) == "" ->
        raise ArgumentError, "input command cannot be empty"

      String.contains?(command, ":") ->
        raise ArgumentError,
              "ffuf input commands cannot contain ':' because ffuf reserves it as the keyword separator"

      is_binary(shell) and String.trim(shell) == "" ->
        raise ArgumentError, "input shell cannot be empty"

      true ->
        %Wordlist{
          ref: "input:#{keyword}",
          keyword: keyword,
          source: {:command, command, count, shell},
          classes: [class]
        }
    end
  end

  defp put_wordlist!(scan, wordlist) do
    case Enum.find(scan.wordlists, &(&1.keyword == wordlist.keyword)) do
      nil -> %{scan | wordlists: scan.wordlists ++ [wordlist]}
      ^wordlist -> scan
      _other -> raise ArgumentError, "keyword #{wordlist.keyword} has conflicting input sources"
    end
  end

  defp normalize_oracle_options!(opts, kind) do
    allowed = [:codes, :lines, :regex, :size, :time, :words, :mode]
    unknown = Keyword.keys(opts) -- allowed
    if unknown != [], do: raise(ArgumentError, "unknown #{kind} options: #{inspect(unknown)}")

    mode = normalize_set_mode(Keyword.get(opts, :mode))
    {size, auto?} = normalize_size(Keyword.get(opts, :size, :not_set), kind)

    criteria =
      %{}
      |> maybe_put(:codes, normalize_codes(Keyword.get(opts, :codes, :not_set)))
      |> maybe_put(:lines, normalize_counts(Keyword.get(opts, :lines, :not_set), :lines))
      |> maybe_put(:regex, normalize_regex(Keyword.get(opts, :regex, :not_set)))
      |> maybe_put(:size, size)
      |> maybe_put(:time, normalize_time(Keyword.get(opts, :time, :not_set)))
      |> maybe_put(:words, normalize_counts(Keyword.get(opts, :words, :not_set), :words))

    {criteria, mode, auto?}
  end

  defp normalize_set_mode(nil), do: nil
  defp normalize_set_mode(mode) when mode in [:and, :or], do: mode

  defp normalize_set_mode(mode),
    do: raise(ArgumentError, "invalid matcher/filter mode: #{inspect(mode)}")

  defp normalize_codes(:not_set), do: :not_set
  defp normalize_codes(:all), do: :all

  defp normalize_codes(codes) when is_list(codes) and codes != [] do
    validate_numeric_values!(codes, :codes, 100..599)
  end

  defp normalize_codes(codes),
    do: raise(ArgumentError, "invalid status-code matcher: #{inspect(codes)}")

  defp normalize_counts(:not_set, _name), do: :not_set
  defp normalize_counts(value, _name) when is_integer(value) and value >= 0, do: value

  defp normalize_counts(values, name) when is_list(values) and values != [] do
    validate_numeric_values!(values, name, 0..2_147_483_647)
  end

  defp normalize_counts(value, name),
    do: raise(ArgumentError, "invalid #{name}: #{inspect(value)}")

  defp validate_numeric_values!(values, name, allowed) do
    valid? =
      Enum.all?(values, fn
        value when is_integer(value) -> value in allowed
        %Range{first: first, last: last, step: 1} -> first in allowed and last in allowed
        _other -> false
      end)

    if valid?, do: values, else: raise(ArgumentError, "invalid #{name}: #{inspect(values)}")
  end

  defp normalize_regex(:not_set), do: :not_set
  defp normalize_regex(%Regex{source: source}), do: source
  defp normalize_regex(regex) when is_binary(regex), do: regex

  defp normalize_regex(regex),
    do: raise(ArgumentError, "invalid regular expression: #{inspect(regex)}")

  defp normalize_size(:not_set, _kind), do: {:not_set, false}
  defp normalize_size(:auto, :matcher), do: {:not_set, true}
  defp normalize_size(value, _kind), do: {normalize_counts(value, :size), false}

  defp normalize_time(:not_set), do: :not_set

  defp normalize_time({comparison, milliseconds})
       when comparison in [:gt, :lt] and is_integer(milliseconds) and milliseconds >= 0,
       do: {comparison, milliseconds}

  defp normalize_time(value),
    do: raise(ArgumentError, "invalid time criterion: #{inspect(value)}")

  defp maybe_put(map, _key, :not_set), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp normalize_targets!(targets) when is_list(targets) and targets != [] do
    Enum.map(targets, &normalize_target!/1)
  end

  defp normalize_targets!([]), do: raise(ArgumentError, "at least one target is required")
  defp normalize_targets!(target), do: [normalize_target!(target)]
  defp normalize_target!(%Target{} = target), do: target
  defp normalize_target!(target) when is_binary(target), do: Target.parse!(target)

  defp normalize_target!(%Seed{value: value, classes: classes} = seed) when is_binary(value) do
    if :target in classes do
      Target.parse!(value)
    else
      raise ArgumentError, "target seeds require the :target class: #{inspect(seed.id)}"
    end
  end

  defp normalize_target!(target), do: raise(ArgumentError, "invalid target: #{inspect(target)}")

  defp normalize_method!(method) do
    method = String.upcase(method)

    if String.match?(method, ~r/^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]*$/) do
      method
    else
      raise ArgumentError, "invalid HTTP method: #{inspect(method)}"
    end
  end

  defp normalize_headers!(headers) do
    Map.new(headers, fn {name, value} ->
      validate_header_name!(name)
      unless is_binary(value), do: raise(ArgumentError, "header values must be strings")
      {name, value}
    end)
  end

  defp validate_header_name!(name) when is_binary(name) do
    if String.match?(name, ~r/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/) do
      :ok
    else
      raise ArgumentError, "invalid header name: #{inspect(name)}"
    end
  end

  defp validate_header_name!(name),
    do: raise(ArgumentError, "invalid header name: #{inspect(name)}")

  defp validate_keyword!(keyword) do
    if String.match?(keyword, ~r/^[A-Za-z][A-Za-z0-9_]*$/) do
      :ok
    else
      raise ArgumentError, "invalid ffuf keyword: #{inspect(keyword)}"
    end
  end

  defp validate_delay!(nil), do: :ok

  defp validate_delay!(delay) do
    unless String.match?(delay, ~r/^\d+(?:\.\d+)?(?:-\d+(?:\.\d+)?)?$/) do
      raise ArgumentError, "delay must be seconds or a seconds range, got: #{inspect(delay)}"
    end
  end

  defp generate_scan_id do
    "foray-#{System.system_time(:millisecond)}-#{System.unique_integer([:positive, :monotonic])}"
  end
end
