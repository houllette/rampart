defmodule Core.Scope.Policy do
  @moduledoc "Behaviour implemented by embedding-system authorization policies."

  @callback authorized?(target :: term(), policy_state :: term()) :: boolean()
end
