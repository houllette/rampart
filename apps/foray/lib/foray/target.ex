defmodule Foray.Target do
  @moduledoc "A normalized absolute HTTP(S) target used by jobs and scope policies."

  @type t :: %__MODULE__{
          original: String.t(),
          url: String.t(),
          scheme: :http | :https,
          host: String.t(),
          port: pos_integer(),
          path: String.t(),
          query: String.t() | nil
        }

  @enforce_keys [:original, :url, :scheme, :host, :port, :path]
  defstruct [:original, :url, :scheme, :host, :port, :path, :query]

  @doc "Parses and normalizes an absolute HTTP or HTTPS URL without resolving DNS."
  @spec parse(String.t()) :: {:ok, t()} | {:error, term()}
  def parse(value) when is_binary(value) do
    case String.trim(value) do
      "" -> {:error, :empty_target}
      value -> parse_url(value)
    end
  end

  def parse(value), do: {:error, {:invalid_target, value}}

  defp parse_url(value) do
    with {:ok, uri} <- URI.new(value),
         {:ok, scheme} <- parse_scheme(uri.scheme),
         {:ok, host} <- normalize_host(uri.host),
         :ok <- validate_uri(uri),
         path <- normalize_path(uri.path),
         normalized_uri <- %{uri | scheme: Atom.to_string(scheme), host: host, path: path},
         url <- URI.to_string(normalized_uri) do
      {:ok,
       %__MODULE__{
         original: value,
         url: url,
         scheme: scheme,
         host: host,
         port: normalized_uri.port,
         path: path,
         query: normalized_uri.query
       }}
    end
  end

  @doc "Parses a target and raises when it is invalid."
  @spec parse!(String.t()) :: t()
  def parse!(value) do
    case parse(value) do
      {:ok, target} ->
        target

      {:error, reason} ->
        raise ArgumentError, "invalid target #{inspect(value)}: #{inspect(reason)}"
    end
  end

  @doc "Replaces a target's path and preserves its origin and query."
  @spec put_path(t(), String.t()) :: t()
  def put_path(%__MODULE__{} = target, path) when is_binary(path) do
    update_uri(target, &%{&1 | path: normalize_path(path)})
  end

  @doc "Replaces a target's encoded query string."
  @spec put_query(t(), String.t() | nil) :: t()
  def put_query(%__MODULE__{} = target, query) when is_binary(query) or is_nil(query) do
    update_uri(target, &%{&1 | query: query})
  end

  @doc "Returns the normalized origin used for aggregate governance and correlation."
  @spec origin(t()) :: {atom(), String.t(), pos_integer()}
  def origin(%__MODULE__{} = target), do: {target.scheme, target.host, target.port}

  defp update_uri(target, update) do
    {:ok, uri} = URI.new(target.url)
    uri = update.(uri)
    {:ok, updated} = parse(URI.to_string(uri))
    %{updated | original: target.original}
  end

  defp parse_scheme(scheme) when is_binary(scheme) do
    case String.downcase(scheme) do
      "http" -> {:ok, :http}
      "https" -> {:ok, :https}
      _other -> {:error, :unsupported_scheme}
    end
  end

  defp parse_scheme(_scheme), do: {:error, :unsupported_scheme}

  defp normalize_host(nil), do: {:error, :missing_host}
  defp normalize_host(""), do: {:error, :missing_host}

  defp normalize_host(host) do
    host = String.downcase(host)

    case :inet.parse_strict_address(String.to_charlist(host)) do
      {:ok, address} -> {:ok, address |> :inet.ntoa() |> List.to_string()}
      {:error, :einval} -> validate_hostname(host)
    end
  end

  defp validate_hostname(host) do
    valid? =
      byte_size(host) <= 253 and
        String.match?(
          host,
          ~r/^(?=.{1,253}\z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\.?$/
        )

    if valid?, do: {:ok, String.trim_trailing(host, ".")}, else: {:error, :invalid_host}
  end

  defp validate_uri(%URI{userinfo: userinfo}) when not is_nil(userinfo),
    do: {:error, :userinfo_forbidden}

  defp validate_uri(%URI{fragment: fragment}) when not is_nil(fragment),
    do: {:error, :fragment_forbidden}

  defp validate_uri(%URI{port: port}) when port not in 1..65_535, do: {:error, :invalid_port}
  defp validate_uri(_uri), do: :ok

  defp normalize_path(nil), do: "/"
  defp normalize_path(""), do: "/"
  defp normalize_path("/" <> _rest = path), do: path
  defp normalize_path(path), do: "/" <> path
end
