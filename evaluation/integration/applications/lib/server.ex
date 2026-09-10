defmodule Fixture.Server do
  @moduledoc false
  def start(plug, variant) do
    {:ok, supervisor} =
      Supervisor.start_link([{Agent, fn -> %{cache: %{}, rotations: 0} end}],
        strategy: :one_for_one
      )

    [{_, store, _, _}] = Supervisor.which_children(supervisor)

    {:ok, listener} =
      Supervisor.start_child(
        supervisor,
        {Bandit,
         plug: {plug, [variant: variant, store: store]},
         ip: {127, 0, 0, 1},
         port: 0,
         startup_log: false}
      )

    {:ok, {_address, port}} = ThousandIsland.listener_info(listener)
    %{supervisor: supervisor, store: store, url: "http://127.0.0.1:#{port}"}
  end

  def stop(server), do: Supervisor.stop(server.supervisor)

  def request(server, method, path, headers \\ []) do
    url = String.to_charlist(server.url <> path)
    headers = Enum.map(headers, fn {k, v} -> {String.to_charlist(k), String.to_charlist(v)} end)

    request =
      if method == :get,
        do: {url, headers},
        else: {url, headers, ~c"application/octet-stream", ""}

    case :httpc.request(method, request, [timeout: 2000, connect_timeout: 1000],
           body_format: :binary
         ) do
      {:ok, {{_, status, _}, headers, body}} ->
        %{
          status: status,
          headers: Map.new(headers, fn {k, v} -> {to_string(k), to_string(v)} end),
          body: body
        }

      {:error, reason} ->
        raise "fixture HTTP execution failed: #{inspect(reason)}"
    end
  end
end
