defmodule Havoc.Oracle do
  @moduledoc """
  Conservative, composable security oracles.

  Oracles report signals and invariants, not exploit confirmation. In
  particular, raw reflection is only a vulnerability when the caller's
  application contract makes reflection unsafe, and a database error proves
  information disclosure rather than SQL injection by itself.
  """

  alias Havoc.Oracle.{AssertionError, Checked, Violation}

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
      with body when is_binary(body) <- response_body(observation),
           payload when is_binary(payload) and payload != "" <- payload,
           true <- reflection_content_type?(observation, config),
           true <- contains_payload?(body, payload, config.case_sensitive) do
        {:error, "payload was reflected verbatim in the response",
         %{content_type: content_type(observation)}}
      else
        _other -> :ok
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
    oracles
    |> normalize!()
    |> check_normalized(observation, payload, context)
  end

  @doc "Runs oracles and raises a structured internal assertion on violation."
  @spec assert!([atom() | t()], observation :: term(), payload :: term(), context :: map()) ::
          Checked.t()
  def assert!(oracles, observation, payload, context \\ %{}) do
    case check(oracles, observation, payload, context) do
      :ok ->
        %Checked{observation: observation}

      {:error, violations} ->
        raise AssertionError,
          violations: violations,
          observation: observation,
          payload: payload
    end
  end

  @doc false
  @spec check_normalized([t()], term(), term(), map()) :: :ok | {:error, [Violation.t()]}
  def check_normalized(oracles, observation, payload, context) do
    violations =
      Enum.reduce(oracles, [], fn oracle, violations ->
        case oracle.check.(observation, payload, context) do
          result when result in [:ok, :skip, true] ->
            violations

          false ->
            [violation(oracle, "oracle predicate returned false", %{}) | violations]

          {:error, evidence} when is_binary(evidence) ->
            [violation(oracle, evidence, %{}) | violations]

          {:error, evidence, details} when is_binary(evidence) and is_map(details) ->
            [violation(oracle, evidence, details) | violations]

          other ->
            raise ArgumentError,
                  "oracle #{oracle.name} returned invalid result: #{inspect(other)}"
        end
      end)
      |> Enum.reverse()

    if violations == [], do: :ok, else: {:error, violations}
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

  defp normalize_one!(:authz_invariant) do
    raise ArgumentError,
          "authz_invariant requires an independent predicate; use Havoc.Oracle.authz_invariant/2"
  end

  defp normalize_one!(oracle) do
    raise ArgumentError, "unknown security oracle: #{inspect(oracle)}"
  end

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
      case Enum.find(patterns, &body_matches?(response_body(observation), &1)) do
        nil -> :ok
        pattern -> {:error, evidence.(pattern), %{pattern: inspect(pattern)}}
      end
    end

    %__MODULE__{name: name, category: category, confidence: confidence, check: checker}
  end

  defp validate_patterns!(patterns) do
    unless patterns != [] and Enum.all?(patterns, &match?(%Regex{}, &1)) do
      raise ArgumentError, "oracle patterns must be a non-empty list of Regex values"
    end

    patterns
  end

  defp body_matches?(body, pattern) when is_binary(body), do: Regex.match?(pattern, body)
  defp body_matches?(_body, _pattern), do: false

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

  defp reflection_content_type?(_observation, %{content_types: :any}), do: true

  defp reflection_content_type?(observation, opts) do
    case content_type(observation) do
      type when is_binary(type) ->
        normalized = String.downcase(type)
        String.starts_with?(normalized, ["text/html", "application/xhtml+xml"])

      nil ->
        opts[:unknown_content_type] == :check
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
