defmodule Portico.Enrichment.Engine do
  @moduledoc "Behaviour implemented by deep host enrichment engines."

  alias Portico.{Discovery.Result, Host}

  @callback option_schema() :: keyword()
  @callback capabilities() :: map()
  @callback required_privileges(keyword()) :: [atom()]
  @callback validate_runtime(keyword()) :: :ok | {:error, term()}
  @callback enrich([Result.t()], keyword()) :: {:ok, [Host.t()]} | {:error, term()}

  @optional_callbacks capabilities: 0, required_privileges: 1, validate_runtime: 1
end
