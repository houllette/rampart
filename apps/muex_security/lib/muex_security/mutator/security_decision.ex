defmodule MuexSecurity.Mutator.SecurityDecision do
  @moduledoc "Mutates narrowly named security allow/deny predicates toward bypass."

  @behaviour Muex.Mutator

  alias MuexSecurity.Mutation

  @allow_predicates [
    :authenticated?,
    :authorized?,
    :allowed?,
    :permitted?,
    :has_permission?,
    :can_access?,
    :trusted?,
    :verified?,
    :valid_signature?,
    :csrf_valid?
  ]

  @deny_predicates [
    :blocked?,
    :denied?,
    :forbidden?,
    :revoked?,
    :expired?,
    :rate_limited?,
    :throttled?
  ]

  @impl true
  def name, do: "SecurityDecision"

  @impl true
  def description, do: "Forces named authorization, trust, token, and throttling decisions"

  @impl true
  def supported_languages, do: [Muex.Language.Elixir]

  @impl true
  def mutate({{:., _dot_metadata, [_receiver, name]}, metadata, args}, context)
      when is_atom(name) and is_list(args) do
    decision_mutation(name, metadata, context)
  end

  def mutate(_ast, _context), do: []

  defp decision_mutation(name, metadata, context) when name in @allow_predicates do
    [Mutation.build(__MODULE__, true, "force #{name} to allow", context, metadata)]
  end

  defp decision_mutation(name, metadata, context) when name in @deny_predicates do
    [Mutation.build(__MODULE__, false, "force #{name} to return false", context, metadata)]
  end

  defp decision_mutation(_name, _metadata, _context), do: []
end
