defmodule Havoc.Target.Phoenix do
  @moduledoc """
  Derives fuzz targets for dynamic Phoenix route path segments.

  Phoenix remains an optional consumer dependency. Havoc calls
  `Phoenix.Router.routes/1` dynamically and does not compile against Phoenix.
  Router metadata does not describe query strings or request bodies, so this
  provider only derives `:id` and `*glob` path parameters. Those richer inputs
  require an OpenAPI/provider adapter or explicit targets.
  """

  @behaviour Havoc.Target.Provider

  alias Havoc.Target

  @schema [
    generator: [type: :any],
    oracles: [type: {:list, :any}, default: [:no_crash, :no_500, :no_reflection]],
    classes: [type: {:list, :atom}, default: [:derived, :http_path]],
    methods: [type: {:list, :atom}, default: []]
  ]

  @impl true
  def derive(router, opts \\ []) when is_atom(router) do
    phoenix_router = Module.concat(["Phoenix", "Router"])

    if Code.ensure_loaded?(phoenix_router) and function_exported?(phoenix_router, :routes, 1) do
      routes = phoenix_router.routes(router)
      derive_routes(routes, Keyword.put(opts, :router, router))
    else
      raise ArgumentError,
            "Phoenix.Router.routes/1 is unavailable; add Phoenix or call derive_routes/2"
    end
  end

  @doc "Derives path-segment targets from an already introspected route list."
  @spec derive_routes([map()], opts :: keyword()) :: [Target.t()]
  def derive_routes(routes, opts \\ []) when is_list(routes) do
    router = Keyword.get(opts, :router)
    opts = opts |> Keyword.delete(:router) |> NimbleOptions.validate!(@schema)
    generator = Keyword.get_lazy(opts, :generator, &Havoc.Gen.all/0)

    routes
    |> Enum.filter(&selected_route?(&1, opts[:methods]))
    |> Enum.flat_map(&targets_for_route(&1, router, generator, opts))
    |> Enum.uniq_by(& &1.id)
    |> Enum.sort_by(& &1.id)
  end

  @doc "Substitutes and RFC 3986-encodes a payload into a derived route path."
  @spec path(Target.t(), payload :: term(), opts :: keyword()) :: String.t()
  def path(%Target{kind: :phoenix_route} = target, payload, opts \\ []) do
    schema = [encode: [type: :boolean, default: true]]
    opts = NimbleOptions.validate!(opts, schema)
    value = to_string(payload)
    value = if opts[:encode], do: URI.encode(value, &URI.char_unreserved?/1), else: value
    String.replace(target.meta.route_path, target.meta.path_token, value, global: false)
  end

  defp selected_route?(%{verb: verb, path: path}, methods)
       when is_atom(verb) and is_binary(path) do
    verb != :* and (methods == [] or verb in methods)
  end

  defp selected_route?(_route, _methods), do: false

  defp targets_for_route(route, router, generator, opts) do
    Enum.map(path_parameters(route.path), fn {token, parameter, location} ->
      method = route.verb |> Atom.to_string() |> String.upcase()
      id = "phoenix:#{method}:#{route.path}:#{location}:#{parameter}"

      %Target{
        id: id,
        kind: :phoenix_route,
        generator: generator,
        module: Map.get(route, :plug),
        function: action(Map.get(route, :plug_opts)),
        parameter: parameter,
        oracles: opts[:oracles],
        classes: opts[:classes],
        locus: %{endpoint: route.path, method: method, param: parameter},
        meta: %{
          provider: :phoenix_router,
          router: router,
          route_path: route.path,
          path_token: token,
          parameter_location: location,
          route_metadata: Map.get(route, :metadata, %{})
        }
      }
    end)
  end

  defp path_parameters(path) do
    ~r/(:[A-Za-z_][A-Za-z0-9_]*|\*[A-Za-z_][A-Za-z0-9_]*)/
    |> Regex.scan(path, capture: :all_but_first)
    |> Enum.map(fn [token] ->
      location = if String.starts_with?(token, "*"), do: :path_glob, else: :path
      {token, String.slice(token, 1..-1//1), location}
    end)
  end

  defp action(value) when is_atom(value), do: value
  defp action(_value), do: nil
end
