defmodule Fixture.TenantCache do
  @moduledoc false
  use Plug.Router

  plug(:match)
  plug(:authenticate)
  plug(:dispatch)

  def init(options), do: options

  def call(conn, options) do
    conn
    |> assign(:variant, options[:variant])
    |> assign(:store, options[:store])
    |> super(options)
  end

  get "/uncached/profile" do
    send_resp(conn, 200, profile(conn.assigns.tenant))
  end

  get "/profile" do
    key =
      if conn.assigns.variant == :fixed,
        do: {conn.assigns.tenant, conn.request_path},
        else: conn.request_path

    {status, body} =
      Agent.get_and_update(conn.assigns.store, fn state ->
        case Map.fetch(state.cache, key) do
          {:ok, body} ->
            {{"hit", body}, state}

          :error ->
            body = profile(conn.assigns.tenant)
            {{"miss", body}, put_in(state.cache[key], body)}
        end
      end)

    conn
    |> put_resp_header("x-cache", status)
    |> put_resp_header("x-cache-key", inspect(key))
    |> send_resp(200, body)
  end

  match _ do
    send_resp(conn, 404, "missing")
  end

  defp authenticate(conn, _options) do
    case get_req_header(conn, "authorization") do
      ["Bearer alpha-fixture-token"] -> assign(conn, :tenant, "alpha")
      ["Bearer beta-fixture-token"] -> assign(conn, :tenant, "beta")
      _ -> conn |> send_resp(401, "unauthorized") |> halt()
    end
  end

  defp profile("alpha"), do: "alpha-private-profile"
  defp profile("beta"), do: "beta-private-profile"
end
