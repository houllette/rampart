defmodule MuexSecurity.Mutator.SecurityHeader do
  @moduledoc "Removes writes of recognized browser security response headers."

  @behaviour Muex.Mutator

  alias MuexSecurity.Mutation

  @headers [
    "content-security-policy",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "permissions-policy",
    "referrer-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options"
  ]

  @impl true
  def name, do: "SecurityHeader"

  @impl true
  def description, do: "Deletes recognized browser security-header writes"

  @impl true
  def supported_languages, do: [Muex.Language.Elixir]

  @impl true
  def mutate(
        {{:., _dot_metadata, [{:__aliases__, _, [:Plug, :Conn]}, :put_resp_header]}, metadata,
         [conn, header, _value]},
        context
      ) do
    header_mutation(conn, header, metadata, context)
  end

  def mutate(_ast, _context), do: []

  defp header_mutation(conn, header, metadata, context) when is_binary(header) do
    normalized = String.downcase(header)

    if normalized in @headers do
      [Mutation.build(__MODULE__, conn, "remove #{normalized}", context, metadata)]
    else
      []
    end
  end

  defp header_mutation(_conn, _header, _metadata, _context), do: []
end
