defmodule Havoc.Target.Provider do
  @moduledoc "Behaviour for conservative, framework-specific target derivation."

  @callback derive(source :: term(), opts :: keyword()) :: [Havoc.Target.t()]
end
