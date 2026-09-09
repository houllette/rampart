defmodule Core.Validator do
  @moduledoc """
  Behaviour implemented by Rampart tools that can validate hypotheses.

  Implementations must be deterministic without an agent. External validators
  may observe a changing target, but for one invocation they must return a
  verdict derived solely from the declared action, concrete request, configured
  policy, and captured observations.
  """

  alias Core.Validation.{Action, Request, Result}

  @callback actions() :: [Action.t()]
  @callback validate(Request.t(), opts :: keyword()) :: Result.t()
end
