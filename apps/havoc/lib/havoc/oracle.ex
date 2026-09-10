defmodule Havoc.Oracle do
  @moduledoc """
  Conservative, composable security oracles.

  Oracles decide the exact invariant encoded by the caller; they never infer a
  broader exploit claim from a weaker observation. A context-specific fixture
  may encode an independently observable exploit effect and all required
  preconditions. In contrast, raw reflection is only a vulnerability when the
  caller's application contract makes reflection unsafe, and a database error
  proves information disclosure rather than SQL injection by itself.
  """

  alias Havoc.Observation.{Cache, Codec, Differential, FieldPolicy, HTTPParameter, State}
  alias Havoc.Oracle.{AssertionError, Checked, Report, Terminal, Violation}
  alias Havoc.TermCodec

  @type checker_result ::
          :ok | :skip | boolean() | {:error, String.t()} | {:error, String.t(), map()}
  @type checker :: (observation :: term(), payload :: term(), context :: map() ->
                      checker_result())

  @type t :: %__MODULE__{
          name: atom(),
          category: atom(),
          confidence: Core.Finding.confidence(),
          check: checker(),
          options: map()
        }

  @enforce_keys [:name, :category, :confidence, :check]
  defstruct [:name, :category, :confidence, :check, options: %{}]

  @database_patterns [
    ~r/you have an error in your SQL syntax/i,
    ~r/\bORA-\d{5}\b/,
    ~r/SQLSTATE\[[A-Z0-9]+\]/i,
    ~r/syntax error at or near ["']/i,
    ~r/unclosed quotation mark after the character string/i,
    ~r/(?:SQL Native Client|ODBC SQL Server Driver|OLE DB Provider)/i
  ]

  @sensitive_patterns [
    ~r/traceback \(most recent call last\)/i,
    ~r/stack[\s_-]*trace/i,
    ~r/uncaught\s+\w*exception/i,
    ~r/\.exs?:\d+(?::\d+)?/,
    ~r/(?:ArgumentError|FunctionClauseError|CaseClauseError|KeyError):/
  ]

  @doc "Returns an oracle that treats response statuses from 500 through 599 as violations."
  @spec no_500(keyword()) :: t()
  def no_500(opts \\ []) do
    schema = [
      minimum: [type: :non_neg_integer, default: 500],
      maximum: [type: :non_neg_integer, default: 599],
      missing: [type: {:in, [:skip, :fail]}, default: :skip]
    ]

    config = opts |> NimbleOptions.validate!(schema) |> Map.new()

    if config.minimum > config.maximum do
      raise ArgumentError, "no_500 minimum cannot exceed maximum"
    end

    checker = fn observation, _payload, _context ->
      status = response_status(observation)

      cond do
        is_integer(status) and status >= config.minimum and status <= config.maximum ->
          {:error, "response returned server-error status #{status}", %{status: status}}

        is_integer(status) ->
          :ok

        config.missing == :skip ->
          :skip

        true ->
          {:error, "response did not expose a status for the no_500 oracle"}
      end
    end

    %__MODULE__{
      name: :no_500,
      category: :crash,
      confidence: :high,
      check: checker,
      options: config
    }
  end

  @doc "Marks successful target execution; target exceptions are handled by `Havoc.Property`."
  @spec no_crash(keyword()) :: t()
  def no_crash(opts \\ []) do
    NimbleOptions.validate!(opts, [])

    %__MODULE__{
      name: :no_crash,
      category: :crash,
      confidence: :high,
      check: fn _observation, _payload, _context -> :ok end
    }
  end

  @doc "Rejects exact raw reflection in HTML responses by default."
  @spec no_reflection(keyword()) :: t()
  def no_reflection(opts \\ []) do
    schema = [
      content_types: [type: {:in, [:html, :any]}, default: :html],
      case_sensitive: [type: :boolean, default: true],
      unknown_content_type: [type: {:in, [:skip, :check]}, default: :skip]
    ]

    config = opts |> NimbleOptions.validate!(schema) |> Map.new()

    checker = fn observation, payload, _context ->
      body = response_body(observation)
      content_mode = reflection_content_type(observation, config)

      cond do
        not is_binary(body) or not is_binary(payload) or payload == "" ->
          :skip

        content_mode == :skip ->
          :skip

        content_mode == :ignore ->
          :ok

        contains_payload?(body, payload, config.case_sensitive) ->
          {:error, "payload was reflected verbatim in the response",
           %{content_type: content_type(observation)}}

        true ->
          :ok
      end
    end

    %__MODULE__{
      name: :no_reflection,
      category: :reflection,
      confidence: :low,
      check: checker,
      options: config
    }
  end

  @doc "Detects specific database error disclosures in a response body."
  @spec no_injection_signal(keyword()) :: t()
  def no_injection_signal(opts \\ []) do
    schema = [patterns: [type: {:list, :any}, default: @database_patterns]]
    opts = NimbleOptions.validate!(opts, schema)
    patterns = validate_patterns!(opts[:patterns])

    pattern_oracle(:no_injection_signal, :injection, :medium, patterns, fn pattern ->
      "response disclosed an injection-related error matching #{inspect(pattern)}"
    end)
  end

  @doc "Detects narrowly scoped stack-trace and exception-detail disclosures."
  @spec no_sensitive_leak(keyword()) :: t()
  def no_sensitive_leak(opts \\ []) do
    schema = [patterns: [type: {:list, :any}, default: @sensitive_patterns]]
    opts = NimbleOptions.validate!(opts, schema)
    patterns = validate_patterns!(opts[:patterns])

    pattern_oracle(:no_sensitive_leak, :sensitive_leak, :medium, patterns, fn pattern ->
      "response disclosed sensitive error details matching #{inspect(pattern)}"
    end)
  end

  @doc "Builds an authorization oracle around an independent policy/result predicate."
  @spec authz_invariant((term(), term() -> checker_result()), keyword()) :: t()
  def authz_invariant(predicate, opts \\ []) when is_function(predicate, 2) do
    schema = [evidence: [type: :string, default: "authorization invariant was violated"]]
    opts = NimbleOptions.validate!(opts, schema)

    checker = fn observation, payload, _context ->
      case predicate.(observation, payload) do
        true ->
          :ok

        :ok ->
          :ok

        false ->
          {:error, opts[:evidence]}

        {:error, evidence} ->
          {:error, evidence}

        {:error, evidence, details} ->
          {:error, evidence, details}

        other ->
          raise ArgumentError,
                "authorization predicate returned invalid result: #{inspect(other)}"
      end
    end

    %__MODULE__{
      name: :authz_invariant,
      category: :authz_bypass,
      confidence: :high,
      check: checker,
      options: Map.new(opts)
    }
  end

  @doc "Rejects unsafe terminal control sequences in a captured terminal byte stream."
  @spec terminal_safety(keyword()) :: t()
  def terminal_safety(opts \\ []) do
    schema = [
      allow_sgr: [type: :boolean, default: true],
      allow_newline: [type: :boolean, default: true],
      allow_tab: [type: :boolean, default: true]
    ]

    config = opts |> NimbleOptions.validate!(schema) |> Map.new()

    checker = fn observation, _payload, _context ->
      observation
      |> terminal_output()
      |> terminal_result(config)
    end

    %__MODULE__{
      name: :terminal_safety,
      category: :terminal_control_injection,
      confidence: :high,
      check: checker,
      options: config
    }
  end

  @doc "Requires every accepted codec input to equal its canonical re-encoding."
  @spec canonical_encoding(keyword()) :: t()
  def canonical_encoding(opts \\ []) do
    NimbleOptions.validate!(opts, [])

    checker = fn
      %Codec{input: input}, payload, _context when input !== payload ->
        raise ArgumentError, "codec observation input does not match the evaluated payload"

      %Codec{status: :rejected}, _payload, _context ->
        :ok

      %Codec{status: :accepted, input: input, reencoded: reencoded}, _payload, _context
      when input === reencoded ->
        :ok

      %Codec{status: :accepted, input: input, reencoded: reencoded}, _payload, _context ->
        {:error, "accepted input is not its codec's canonical encoding",
         %{
           input_fingerprint: TermCodec.fingerprint(input),
           reencoded_fingerprint: TermCodec.fingerprint(reencoded)
         }}

      _observation, _payload, _context ->
        :skip
    end

    %__MODULE__{
      name: :canonical_encoding,
      category: :alternate_encoding,
      confidence: :high,
      check: checker,
      options: %{}
    }
  end

  @doc "Requires a parsed quoted HTTP parameter to preserve its intended value and grammar."
  @spec quoted_parameter_integrity(keyword()) :: t()
  def quoted_parameter_integrity(opts \\ []) do
    schema = [require_quoted: [type: :boolean, default: true]]
    config = opts |> NimbleOptions.validate!(schema) |> Map.new()

    checker = fn
      %HTTPParameter{} = observation, payload, _context ->
        check_http_parameter(observation, payload, config)

      _observation, _payload, _context ->
        :skip
    end

    %__MODULE__{
      name: :quoted_parameter_integrity,
      category: :http_parameter_injection,
      confidence: :high,
      check: checker,
      options: config
    }
  end

  @doc "Rejects observed reuse of one partition's variant through a shared cache."
  @spec cache_partition_noninterference(keyword()) :: t()
  def cache_partition_noninterference(opts \\ []) do
    NimbleOptions.validate!(opts, [])

    checker = fn
      %Cache{} = observation, payload, _context ->
        check_cache_partition(observation, payload)

      _observation, _payload, _context ->
        :skip
    end

    %__MODULE__{
      name: :cache_partition_noninterference,
      category: :cross_tenant_cache_confusion,
      confidence: :high,
      check: checker,
      options: %{}
    }
  end

  @doc "Requires protected fields to remain hidden for a paired restricted actor on every path."
  @spec field_policy_noninterference(keyword()) :: t()
  def field_policy_noninterference(opts \\ []) do
    NimbleOptions.validate!(opts, [])

    checker = fn
      %FieldPolicy{} = observation, payload, _context ->
        check_field_policy(observation, payload)

      _observation, _payload, _context ->
        :skip
    end

    %__MODULE__{
      name: :field_policy_noninterference,
      category: :field_policy_bypass,
      confidence: :high,
      check: checker,
      options: %{}
    }
  end

  @doc "Checks a paired control/treatment observation with an independent relation predicate."
  @spec differential(atom(), (term(), term(), term() -> checker_result()), keyword()) :: t()
  def differential(name, predicate, opts \\ [])
      when is_atom(name) and is_function(predicate, 3) do
    schema = [
      category: [type: :atom, required: true],
      confidence: [type: {:in, [:low, :medium, :high]}, default: :high],
      evidence: [type: :string, default: "differential security invariant was violated"]
    ]

    config = opts |> NimbleOptions.validate!(schema) |> Map.new()

    checker = fn
      %Differential{control: control, treatment: treatment}, payload, _context ->
        predicate.(control, treatment, payload)
        |> independent_predicate_result(config.evidence)

      _observation, _payload, _context ->
        :skip
    end

    %__MODULE__{
      name: name,
      category: config.category,
      confidence: config.confidence,
      check: checker,
      options: config
    }
  end

  @doc "Enforces a finite growth budget and optional post-cleanup reclamation bound."
  @spec bounded_state_growth(keyword()) :: t()
  def bounded_state_growth(opts) when is_list(opts) do
    schema = [
      max_delta: [type: :non_neg_integer, required: true],
      require_reclaimed: [type: :boolean, default: false],
      reclaimed_tolerance: [type: :non_neg_integer, default: 0]
    ]

    config = opts |> NimbleOptions.validate!(schema) |> Map.new()

    checker = fn
      %State{} = state, _payload, _context ->
        check_state_growth(state, config)

      _observation, _payload, _context ->
        :skip
    end

    %__MODULE__{
      name: :bounded_state_growth,
      category: :resource_exhaustion,
      confidence: :high,
      check: checker,
      options: config
    }
  end

  @doc "Builds a named custom oracle."
  @spec custom(atom(), (term(), term() -> checker_result()), keyword()) :: t()
  def custom(name, checker, opts \\ []) when is_atom(name) and is_function(checker, 2) do
    schema = [
      category: [type: :atom, default: :custom],
      confidence: [type: {:in, [:low, :medium, :high]}, default: :medium]
    ]

    opts = NimbleOptions.validate!(opts, schema)

    %__MODULE__{
      name: name,
      category: opts[:category],
      confidence: opts[:confidence],
      check: fn observation, payload, _context -> checker.(observation, payload) end,
      options: Map.new(opts)
    }
  end

  @doc "Normalizes and composes oracle declarations."
  @spec compose([atom() | t() | list()]) :: [t()]
  def compose(oracles), do: normalize!(oracles)

  @doc "Normalizes built-in atom names and explicit oracle values."
  @spec normalize!([atom() | t() | list()]) :: [t()]
  def normalize!(oracles) when is_list(oracles) do
    oracles
    |> List.flatten()
    |> Enum.map(&normalize_one!/1)
  end

  @doc "Runs all oracles, collecting every violation in declaration order."
  @spec check([atom() | t()], observation :: term(), payload :: term(), context :: map()) ::
          :ok | {:error, [Violation.t()]}
  def check(oracles, observation, payload, context \\ %{}) when is_map(context) do
    case evaluate(oracles, observation, payload, context) do
      %Report{violations: []} -> :ok
      %Report{violations: violations} -> {:error, violations}
    end
  end

  @doc "Evaluates all oracles while retaining which checks passed or skipped."
  @spec evaluate([atom() | t()], observation :: term(), payload :: term(), context :: map()) ::
          Report.t()
  def evaluate(oracles, observation, payload, context \\ %{}) when is_map(context) do
    oracles
    |> normalize!()
    |> evaluate_normalized(observation, payload, context)
  end

  @doc "Runs oracles and raises a structured internal assertion on violation."
  @spec assert!([atom() | t()], observation :: term(), payload :: term(), context :: map()) ::
          Checked.t()
  def assert!(oracles, observation, payload, context \\ %{}) do
    case evaluate(oracles, observation, payload, context) do
      %Report{violations: []} = report ->
        %Checked{observation: observation, report: report}

      %Report{violations: violations} ->
        raise AssertionError,
          violations: violations,
          observation: observation,
          payload: payload
    end
  end

  @doc false
  @spec check_normalized([t()], term(), term(), map()) :: :ok | {:error, [Violation.t()]}
  def check_normalized(oracles, observation, payload, context) do
    case evaluate_normalized(oracles, observation, payload, context) do
      %Report{violations: []} -> :ok
      %Report{violations: violations} -> {:error, violations}
    end
  end

  @doc false
  @spec evaluate_normalized([t()], term(), term(), map()) :: Report.t()
  def evaluate_normalized(oracles, observation, payload, context) do
    {passed, skipped, violations} =
      Enum.reduce(oracles, {[], [], []}, fn oracle, {passed, skipped, violations} ->
        case oracle.check.(observation, payload, context) do
          result when result in [:ok, true] ->
            {[oracle.name | passed], skipped, violations}

          :skip ->
            {passed, [oracle.name | skipped], violations}

          false ->
            {passed, skipped,
             [violation(oracle, "oracle predicate returned false", %{}) | violations]}

          {:error, evidence} when is_binary(evidence) ->
            {passed, skipped, [violation(oracle, evidence, %{}) | violations]}

          {:error, evidence, details} when is_binary(evidence) and is_map(details) ->
            {passed, skipped, [violation(oracle, evidence, details) | violations]}

          other ->
            raise ArgumentError,
                  "oracle #{oracle.name} returned invalid result: #{inspect(other)}"
        end
      end)

    %Report{
      passed: Enum.reverse(passed),
      skipped: Enum.reverse(skipped),
      violations: Enum.reverse(violations)
    }
  end

  @doc false
  @spec crash_violation(:error | :exit | :throw, term(), list()) :: Violation.t()
  def crash_violation(kind, reason, stacktrace) do
    formatted = Exception.format_banner(kind, reason, stacktrace)

    %Violation{
      oracle: :no_crash,
      category: :crash,
      confidence: :high,
      evidence: "target raised during security property: #{formatted}",
      details: %{kind: kind, reason: reason}
    }
  end

  defp normalize_one!(%__MODULE__{} = oracle), do: oracle
  defp normalize_one!(:no_500), do: no_500()
  defp normalize_one!(:no_crash), do: no_crash()
  defp normalize_one!(:no_reflection), do: no_reflection()
  defp normalize_one!(:no_injection_signal), do: no_injection_signal()
  defp normalize_one!(:no_sensitive_leak), do: no_sensitive_leak()
  defp normalize_one!(:terminal_safety), do: terminal_safety()
  defp normalize_one!(:canonical_encoding), do: canonical_encoding()
  defp normalize_one!(:quoted_parameter_integrity), do: quoted_parameter_integrity()
  defp normalize_one!(:cache_partition_noninterference), do: cache_partition_noninterference()
  defp normalize_one!(:field_policy_noninterference), do: field_policy_noninterference()

  defp normalize_one!(:authz_invariant) do
    raise ArgumentError,
          "authz_invariant requires an independent predicate; use Havoc.Oracle.authz_invariant/2"
  end

  defp normalize_one!(oracle) do
    raise ArgumentError, "unknown security oracle: #{inspect(oracle)}"
  end

  defp check_http_parameter(%HTTPParameter{input: input}, payload, _config)
       when input !== payload do
    raise ArgumentError, "HTTP parameter observation input does not match the evaluated payload"
  end

  defp check_http_parameter(%HTTPParameter{status: :incomplete}, _payload, _config), do: :skip

  defp check_http_parameter(%HTTPParameter{status: :malformed} = observation, _payload, _config) do
    {:error, "authentication header is malformed at the quoted-parameter boundary",
     %{
       header_fingerprint: TermCodec.fingerprint(observation.header),
       parameter: observation.parameter,
       reason: observation.reason
     }}
  end

  defp check_http_parameter(%HTTPParameter{} = observation, _payload, config) do
    occurrences =
      Enum.filter(observation.parameters, &(&1.name == observation.parameter))

    cond do
      scheme_mismatch?(observation) ->
        {:error, "authentication header scheme does not match the expected scheme",
         %{
           actual_scheme: observation.scheme,
           expected_scheme: observation.expected_scheme,
           parameter: observation.parameter
         }}

      length(occurrences) != 1 ->
        {:error, "authentication parameter did not occur exactly once",
         %{
           occurrence_count: length(occurrences),
           parameter: observation.parameter,
           parsed_parameter_names: Enum.map(observation.parameters, & &1.name)
         }}

      config.require_quoted and not hd(occurrences).quoted? ->
        {:error, "authentication parameter was not represented as a quoted-string",
         %{parameter: observation.parameter}}

      hd(occurrences).value !== observation.expected_value ->
        {:error, "quoted authentication parameter did not preserve its intended value",
         %{
           actual_value_fingerprint: TermCodec.fingerprint(hd(occurrences).value),
           expected_value_fingerprint: TermCodec.fingerprint(observation.expected_value),
           parameter: observation.parameter,
           parsed_parameter_names: Enum.map(observation.parameters, & &1.name)
         }}

      true ->
        :ok
    end
  end

  defp scheme_mismatch?(%HTTPParameter{expected_scheme: nil}), do: false

  defp scheme_mismatch?(observation) do
    String.downcase(observation.scheme, :ascii) !=
      String.downcase(observation.expected_scheme, :ascii)
  end

  defp check_cache_partition(%Cache{input: input}, payload) when input !== payload do
    raise ArgumentError, "cache observation input does not match the evaluated payload"
  end

  defp check_cache_partition(%Cache{} = observation, _payload) do
    cond do
      observation.first_partition === observation.second_partition ->
        raise ArgumentError, "cache noninterference requires two distinct partitions"

      observation.first_value === observation.direct_second_value ->
        :skip

      observation.served_second_value === observation.direct_second_value ->
        :ok

      cache_reused_first_partition?(observation) ->
        {:error, "a shared cache replayed one partition's variant to another partition",
         %{
           cache_key_fingerprint: TermCodec.fingerprint(observation.first_cache_key),
           direct_second_value_fingerprint:
             TermCodec.fingerprint(observation.direct_second_value),
           leaked_first_value_fingerprint: TermCodec.fingerprint(observation.first_value),
           second_cache_status: observation.second_cache_status
         }}

      true ->
        :skip
    end
  end

  defp cache_reused_first_partition?(observation) do
    observation.second_cache_status == :hit and
      observation.first_cache_key === observation.second_cache_key and
      observation.served_second_value === observation.first_value
  end

  defp check_field_policy(%FieldPolicy{input: input}, payload) when input !== payload do
    raise ArgumentError, "field-policy observation input does not match the evaluated payload"
  end

  defp check_field_policy(%FieldPolicy{} = observation, _payload) do
    if observation.privileged_actor === observation.restricted_actor do
      raise ArgumentError, "field-policy noninterference requires two distinct actors"
    end

    case complete_field_accesses(observation) do
      {:ok, accesses} -> field_policy_result(accesses)
      :incomplete -> :skip
    end
  end

  defp field_policy_result(accesses) do
    case Enum.filter(accesses, &match?({:visible, _value}, &1.restricted)) do
      [] ->
        :ok

      leaks ->
        {:error, "a restricted actor observed a field protected by the paired policy contract",
         %{
           leaks:
             Enum.map(leaks, fn leak ->
               %{
                 field: leak.field,
                 path: leak.path,
                 value_fingerprint: TermCodec.fingerprint(elem(leak.restricted, 1))
               }
             end)
         }}
    end
  end

  defp complete_field_accesses(observation) do
    accesses =
      for path <- observation.paths,
          field <- observation.protected_fields do
        %{
          path: path.name,
          field: field,
          privileged: Map.get(path.privileged, field, :missing),
          restricted: Map.get(path.restricted, field, :missing)
        }
      end

    complete? =
      Enum.all?(accesses, fn access ->
        match?({:visible, _value}, access.privileged) and access.restricted != :missing
      end)

    if complete?, do: {:ok, accesses}, else: :incomplete
  end

  defp independent_predicate_result(result, _evidence) when result in [:ok, :skip, true],
    do: result

  defp independent_predicate_result(false, evidence), do: {:error, evidence}
  defp independent_predicate_result({:error, _message} = result, _evidence), do: result
  defp independent_predicate_result({:error, _message, _details} = result, _evidence), do: result
  defp independent_predicate_result(result, _evidence), do: result

  defp check_state_growth(state, config) do
    growth = state.after - state.before
    settled_delta = if is_integer(state.settled), do: state.settled - state.before

    cond do
      growth > config.max_delta ->
        {:error, "observed external-state growth exceeded the configured security budget",
         state_growth_details(state, growth, settled_delta, config)}

      config.require_reclaimed and is_nil(state.settled) ->
        :skip

      config.require_reclaimed and settled_delta > config.reclaimed_tolerance ->
        {:error, "external state was not reclaimed within the configured security budget",
         state_growth_details(state, growth, settled_delta, config)}

      true ->
        :ok
    end
  end

  defp state_growth_details(state, growth, settled_delta, config) do
    %{
      before: state.before,
      after: state.after,
      settled: state.settled,
      growth: growth,
      settled_delta: settled_delta,
      unit: state.unit,
      max_delta: config.max_delta,
      reclaimed_tolerance: config.reclaimed_tolerance
    }
  end

  defp terminal_output(output) when is_binary(output), do: output

  defp terminal_output(observation) do
    value(observation, [:terminal_output, "terminal_output", :output, "output"])
  end

  defp terminal_result(output, config) when is_binary(output) do
    case Terminal.unsafe_sequences(output, Map.to_list(config)) do
      {:ok, []} ->
        :ok

      {:ok, unsafe} ->
        {:error, "unsafe control sequences reached terminal output", %{sequences: unsafe}}

      {:error, reason} ->
        {:error, "terminal output could not be safely classified", %{reason: reason}}
    end
  end

  defp terminal_result(_missing, _config), do: :skip

  defp violation(oracle, evidence, details) do
    %Violation{
      oracle: oracle.name,
      category: oracle.category,
      confidence: oracle.confidence,
      evidence: evidence,
      details: details
    }
  end

  defp pattern_oracle(name, category, confidence, patterns, evidence) do
    checker = fn observation, _payload, _context ->
      observation
      |> response_body()
      |> pattern_result(patterns, evidence)
    end

    %__MODULE__{name: name, category: category, confidence: confidence, check: checker}
  end

  defp pattern_result(body, patterns, evidence) when is_binary(body) do
    case Enum.find(patterns, &Regex.match?(&1, body)) do
      nil -> :ok
      pattern -> {:error, evidence.(pattern), %{pattern: inspect(pattern)}}
    end
  end

  defp pattern_result(_missing, _patterns, _evidence), do: :skip

  defp validate_patterns!(patterns) do
    unless patterns != [] and Enum.all?(patterns, &match?(%Regex{}, &1)) do
      raise ArgumentError, "oracle patterns must be a non-empty list of Regex values"
    end

    patterns
  end

  defp response_status(observation) do
    value(observation, [:status, "status", :status_code, "status_code"])
  end

  defp response_body(observation) do
    value(observation, [:resp_body, "resp_body", :body, "body"])
  end

  defp content_type(observation) do
    value(observation, [:content_type, "content_type"]) || header_content_type(observation)
  end

  defp header_content_type(observation) do
    headers = value(observation, [:resp_headers, "resp_headers", :headers, "headers"])

    Enum.find_value(headers || [], fn
      {name, value} when is_binary(name) and is_binary(value) ->
        if String.downcase(name) == "content-type", do: value

      _other ->
        nil
    end)
  end

  defp reflection_content_type(_observation, %{content_types: :any}), do: :check

  defp reflection_content_type(observation, opts) do
    case content_type(observation) do
      type when is_binary(type) ->
        normalized = String.downcase(type)

        if String.starts_with?(normalized, ["text/html", "application/xhtml+xml"]),
          do: :check,
          else: :ignore

      nil ->
        if opts[:unknown_content_type] == :check, do: :check, else: :skip
    end
  end

  defp contains_payload?(body, payload, true), do: :binary.match(body, payload) != :nomatch

  defp contains_payload?(body, payload, false) do
    String.valid?(body) and String.valid?(payload) and
      String.contains?(String.downcase(body), String.downcase(payload))
  end

  defp value(map, keys) when is_map(map) do
    Enum.find_value(keys, &Map.get(map, &1))
  end

  defp value(_observation, _keys), do: nil
end
