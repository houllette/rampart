defmodule Fixture.RouteGateway.Rotation do
  @moduledoc false
  use Plug.Router
  plug(:match)
  plug(:dispatch)

  post "/rotate" do
    Agent.update(conn.assigns.store, &Map.update!(&1, :rotations, fn n -> n + 1 end))
    send_resp(conn, 201, "rotated")
  end

  match _ do
    send_resp(conn, 404, "missing")
  end
end

defmodule Fixture.RouteGateway do
  @moduledoc false
  use Plug.Router
  plug(:match)
  plug(:authorize)
  plug(:dispatch)

  def init(options), do: options

  def call(conn, options) do
    conn
    |> assign(:variant, options[:variant])
    |> assign(:store, options[:store])
    |> super(options)
  end

  forward("/api", to: Fixture.RouteGateway.Rotation)
  forward("/legacy", to: Fixture.RouteGateway.Rotation)

  match _ do
    send_resp(conn, 404, "missing")
  end

  defp authorize(conn, _options) do
    protected = conn.assigns.variant == :fixed or String.starts_with?(conn.request_path, "/api/")

    if protected and get_req_header(conn, "authorization") != ["Bearer admin-fixture-token"] do
      conn |> send_resp(403, "forbidden") |> halt()
    else
      conn
    end
  end
end
