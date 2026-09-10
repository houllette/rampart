defmodule RampartEvaluation.Historical.CacheTenancy do
  @moduledoc false

  alias Havoc.Observation.Cache

  def vulnerable(input) when is_map(input) do
    observation = observe(input, :public)
    observation
  end

  def fixed(input) when is_map(input) do
    observation = observe(input, :private)
    observation
  end

  defp observe(%{first_tenant: first, second_tenant: second, path: path} = input, policy) do
    first_response = metadata_response(first, path, policy)
    direct_second_response = metadata_response(second, path, policy)
    first_key = shared_cache_key(path)
    second_key = shared_cache_key(path)
    cache = maybe_store(%{}, first_key, first_response)

    {served_second_response, cache_status} =
      case Map.fetch(cache, second_key) do
        {:ok, response} -> {response, :hit}
        :error -> {direct_second_response, :miss}
      end

    Cache.new!(
      input: input,
      first_partition: first,
      second_partition: second,
      first_cache_key: first_key,
      second_cache_key: second_key,
      first_value: security_projection(first_response),
      direct_second_value: security_projection(direct_second_response),
      served_second_value: security_projection(served_second_response),
      second_cache_status: cache_status,
      metadata: %{
        boundary: :plug_response,
        first_cache_control: Plug.Conn.get_resp_header(first_response, "cache-control"),
        second_cache_control: Plug.Conn.get_resp_header(direct_second_response, "cache-control")
      }
    )
  end

  defp metadata_response(tenant, path, policy) do
    cache_control =
      case policy do
        :public -> "public, max-age=3600"
        :private -> "private, max-age=3600"
      end

    body = ~s|{"issuer":"https://#{tenant}.app.example.test#{path}"}|

    :get
    |> Plug.Test.conn(path)
    |> Plug.Conn.put_resp_header("content-type", "application/json")
    |> Plug.Conn.put_resp_header("cache-control", cache_control)
    |> Plug.Conn.send_resp(200, body)
  end

  defp maybe_store(cache, key, response) do
    if shared_cacheable?(response) do
      Map.put(cache, key, response)
    else
      cache
    end
  end

  defp shared_cacheable?(response) do
    directives =
      response
      |> Plug.Conn.get_resp_header("cache-control")
      |> Enum.flat_map(&String.split(&1, ","))
      |> Enum.map(&(&1 |> String.trim() |> String.downcase()))

    "public" in directives and "private" not in directives and "no-store" not in directives
  end

  defp shared_cache_key(path), do: {:get, path}
  defp security_projection(response), do: %{status: response.status, body: response.resp_body}
end
