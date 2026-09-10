defmodule RampartSAST.Behavior.Ash do
  @moduledoc """
  High-recall, package-specific behavior vocabulary for reviewed Ash APIs.

  These annotations identify candidate policy and field-materialization
  boundaries. They do not establish the actor, authorization options, field
  sensitivity, runtime reachability, or a policy bypass.
  """

  @behaviour RampartSAST.Behavior

  alias RampartSAST.Fact

  @id "rampart.ash-behaviors.v1"

  @classifications %{
    {"Ash", "aggregate"} => :field_aggregate_read,
    {"Ash.Query", "aggregate"} => :field_aggregate_read,
    {"Ash", "load"} => :field_materialization,
    {"Ash", "load!"} => :field_materialization,
    {"Ash.Query", "load"} => :field_materialization,
    {"Ash", "read"} => :resource_read,
    {"Ash", "read!"} => :resource_read,
    {"Ash.Query", "for_read"} => :resource_read_configuration,
    {"Ash", "can"} => :authorization_decision,
    {"Ash", "can?"} => :authorization_decision,
    {"Ash", "can!"} => :authorization_decision,
    {"Ash.PlugHelpers", "get_tenant"} => :tenant_context_read,
    {"Ash.PlugHelpers", "set_tenant"} => :tenant_context_write
  }

  @impl true
  @spec id() :: String.t()
  def id, do: @id

  @impl true
  @spec classify(Fact.t(), keyword()) :: [RampartSAST.Behavior.classification()]
  def classify(%Fact{kind: kind} = fact, _options) when kind in [:call, :unqualified_call] do
    key = {fact.attributes.target_module, fact.attributes.target_function}

    case Map.fetch(@classifications, key) do
      {:ok, behavior} ->
        [
          %{
            behavior: behavior,
            basis: :reviewed_package_api,
            attributes: %{contract_family: :ash_authorization}
          }
        ]

      :error ->
        []
    end
  end

  def classify(_fact, _options), do: []
end
