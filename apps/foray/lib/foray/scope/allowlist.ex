defmodule Foray.Scope.Allowlist do
  @moduledoc """
  A scheme-, host-, port-, and path-aware HTTP target policy.

  Entries are absolute URLs. A host may begin with `*.` to authorize subdomains
  but not the apex. Paths authorize that exact path and descendants on segment
  boundaries.
  """

  @behaviour Core.Scope.Policy

  alias Foray.Target

  defmodule Rule do
    @moduledoc "A normalized immutable URL authorization rule."
    @type t :: %__MODULE__{
            scheme: :http | :https,
            host: String.t(),
            port: pos_integer(),
            path: String.t(),
            wildcard?: boolean()
          }

    @enforce_keys [:scheme, :host, :port, :path, :wildcard?]
    defstruct [:scheme, :host, :port, :path, :wildcard?]
  end

  @type t :: %__MODULE__{rules: [Rule.t()]}
  defstruct rules: []

  @doc "Builds an HTTP scope allowlist. Empty entries authorize nothing."
  @spec new([String.t()]) :: {:ok, t()} | {:error, term()}
  def new(entries) when is_list(entries) do
    entries
    |> Enum.reduce_while({:ok, []}, fn entry, {:ok, rules} ->
      case parse_rule(entry) do
        {:ok, rule} -> {:cont, {:ok, [rule | rules]}}
        {:error, reason} -> {:halt, {:error, {entry, reason}}}
      end
    end)
    |> case do
      {:ok, rules} -> {:ok, %__MODULE__{rules: Enum.reverse(rules)}}
      error -> error
    end
  end

  @doc "Builds an allowlist and raises when an entry is invalid."
  @spec new!([String.t()]) :: t()
  def new!(entries) do
    case new(entries) do
      {:ok, policy} -> policy
      {:error, reason} -> raise ArgumentError, "invalid Foray scope: #{inspect(reason)}"
    end
  end

  @impl true
  def authorized?(%Target{} = target, %__MODULE__{} = policy) do
    Enum.any?(policy.rules, &contains?(&1, target))
  end

  def authorized?(target, %__MODULE__{} = policy) when is_binary(target) do
    case Target.parse(target) do
      {:ok, target} -> authorized?(target, policy)
      {:error, _reason} -> false
    end
  end

  def authorized?(_target, %__MODULE__{}), do: false

  defp parse_rule(entry) when is_binary(entry) do
    with {:ok, wildcard?, parseable} <- wildcard_url(entry),
         {:ok, target} <- Target.parse(parseable),
         {:ok, path} <- canonical_path(target.path) do
      host =
        if wildcard?, do: String.replace_prefix(target.host, "wildcard.", ""), else: target.host

      {:ok,
       %Rule{
         scheme: target.scheme,
         host: host,
         port: target.port,
         path: path,
         wildcard?: wildcard?
       }}
    end
  end

  defp parse_rule(_entry), do: {:error, :invalid_rule}

  defp wildcard_url(entry) do
    case Regex.run(~r/^(https?):\/\/\*\.(.+)$/i, String.trim(entry)) do
      [_, scheme, rest] -> {:ok, true, String.downcase(scheme) <> "://wildcard." <> rest}
      nil -> {:ok, false, entry}
    end
  end

  defp contains?(rule, target) do
    with true <- rule.scheme == target.scheme,
         true <- rule.port == target.port,
         true <- host_allowed?(rule, target.host),
         {:ok, path} <- canonical_path(target.path) do
      path_allowed?(rule.path, path)
    else
      _other -> false
    end
  end

  defp host_allowed?(%Rule{wildcard?: false, host: host}, candidate), do: host == candidate

  defp host_allowed?(%Rule{wildcard?: true, host: suffix}, candidate) do
    candidate != suffix and String.ends_with?(candidate, "." <> suffix)
  end

  defp path_allowed?("/", _candidate), do: true
  defp path_allowed?(allowed, allowed), do: true
  defp path_allowed?(allowed, candidate), do: String.starts_with?(candidate, allowed <> "/")

  defp canonical_path(path) do
    decoded = URI.decode(path)
    {:ok, Path.expand(decoded, "/")}
  rescue
    ArgumentError -> {:error, :invalid_path_encoding}
  end
end
