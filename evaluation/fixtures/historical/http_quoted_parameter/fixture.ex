defmodule RampartEvaluation.Historical.HTTPQuotedParameter do
  @moduledoc false

  alias Havoc.Observation.HTTPParameter

  def vulnerable(tenant) when is_binary(tenant) do
    metadata_url = metadata_url(tenant)
    challenge = ~s|Bearer resource_metadata="#{metadata_url}"|

    conn =
      :get
      |> Plug.Test.conn("/")
      |> Plug.Conn.put_resp_header("www-authenticate", challenge)
      |> Plug.Conn.send_resp(401, "")

    conn
    |> Plug.Conn.get_resp_header("www-authenticate")
    |> List.first()
    |> HTTPParameter.authentication("resource_metadata", metadata_url,
      input: tenant,
      scheme: "Bearer",
      metadata: %{boundary: :plug_response}
    )
  end

  def fixed(tenant) when is_binary(tenant) do
    metadata_url = metadata_url(tenant)
    escaped = metadata_url |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\"")
    challenge = ~s|Bearer resource_metadata="#{escaped}"|

    conn =
      :get
      |> Plug.Test.conn("/")
      |> Plug.Conn.put_resp_header("www-authenticate", challenge)
      |> Plug.Conn.send_resp(401, "")

    conn
    |> Plug.Conn.get_resp_header("www-authenticate")
    |> List.first()
    |> HTTPParameter.authentication("resource_metadata", metadata_url,
      input: tenant,
      scheme: "Bearer",
      metadata: %{boundary: :plug_response}
    )
  end

  defp metadata_url(tenant), do: "https://#{tenant}.app.example.test/.well-known/oauth"
end
