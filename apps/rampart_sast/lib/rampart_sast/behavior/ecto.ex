defmodule RampartSAST.Behavior.Ecto do
  @moduledoc "High-recall, package-specific behavior vocabulary for reviewed Ecto APIs."

  @behaviour RampartSAST.Behavior

  alias RampartSAST.Fact

  @id "rampart.ecto-behaviors.v1"

  @classifications %{
    {"Ecto.Adapters.SQL", "query"} => :raw_database_query,
    {"Ecto.Adapters.SQL", "query!"} => :raw_database_query,
    {"Ecto.Adapters.SQL", "to_sql"} => :database_query_render,
    {"Ecto.Query", "fragment"} => :database_query_fragment,
    {"Ecto.Query", "dynamic"} => :dynamic_database_query,
    {"Ecto.Changeset", "cast"} => :external_data_cast,
    {"Ecto.Changeset", "change"} => :data_change,
    {"Ecto.Changeset", "unsafe_validate_unique"} => :database_uniqueness_check,
    {"Ecto.Multi", "run"} => :database_transaction_callback,
    {"Ecto.Multi", "insert"} => :database_write,
    {"Ecto.Multi", "update"} => :database_write,
    {"Ecto.Multi", "delete"} => :database_write
  }

  @impl true
  @spec id() :: String.t()
  def id, do: @id

  @impl true
  @spec classify(Fact.t(), keyword()) :: [RampartSAST.Behavior.classification()]
  def classify(%Fact{kind: kind} = fact, _options) when kind in [:call, :unqualified_call] do
    key = {fact.attributes.target_module, fact.attributes.target_function}

    case Map.fetch(@classifications, key) do
      {:ok, behavior} -> [%{behavior: behavior, basis: :reviewed_package_api}]
      :error -> []
    end
  end

  def classify(_fact, _options), do: []
end
