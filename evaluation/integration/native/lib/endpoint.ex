defmodule NativeFixture.Endpoint do
  @moduledoc false
  import Plug.Conn
  def init(options), do: options

  def call(conn, options) do
    {:ok, body, conn} = read_body(conn)

    Agent.update(options[:requests], fn requests ->
      [
        %{
          path: conn.request_path,
          query: conn.query_string,
          body: body,
          headers: conn.req_headers,
          at: System.monotonic_time(:millisecond)
        }
        | requests
      ]
    end)

    path =
      if conn.request_path == "/switch",
        do: Agent.get(options[:mode], & &1),
        else: conn.request_path

    case path do
      :silent ->
        Process.sleep(30_000)
        send_resp(conn, 200, "late")

      :missing ->
        send_resp(conn, 404, "missing")

      "/silent" ->
        Process.sleep(30_000)
        send_resp(conn, 200, "late")

      "/missing" ->
        send_resp(conn, 404, "missing")

      _ ->
        send_resp(conn, 200, "native-fixture")
    end
  end
end

defmodule NativeFixture.Runner do
  @moduledoc false
  @behaviour Core.Runner
  @impl true
  def run(command, options), do: Core.Runner.Exile.run(command, options)
  @impl true
  def stream([_executable | arguments], options),
    do: Core.Runner.Exile.stream([Path.expand("observed/ffuf") | arguments], options)
end
