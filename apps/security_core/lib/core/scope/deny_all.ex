defmodule Core.Scope.DenyAll do
  @moduledoc "Fail-closed policy used when no authorization policy is configured."

  @behaviour Core.Scope.Policy

  @impl true
  def authorized?(_target, _policy_state), do: false
end
