defmodule MuexSecurity.Mutator.TransportSecurity do
  @moduledoc "Weakens explicit TLS peer and hostname verification options."

  @behaviour Muex.Mutator

  alias MuexSecurity.Mutation

  @impl true
  def name, do: "TransportSecurity"

  @impl true
  def description, do: "Disables explicit TLS peer or hostname verification"

  @impl true
  def supported_languages, do: [Muex.Language.Elixir]

  @impl true
  def mutate({:verify, :verify_peer}, context) do
    [
      Mutation.build(
        __MODULE__,
        {:verify, :verify_none},
        "verify_peer to verify_none",
        context,
        []
      )
    ]
  end

  def mutate({:check_hostname, true}, context) do
    [
      Mutation.build(
        __MODULE__,
        {:check_hostname, false},
        "disable hostname verification",
        context,
        []
      )
    ]
  end

  def mutate(_ast, _context), do: []
end
