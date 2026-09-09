defmodule RampartIAST do
  @moduledoc """
  Experimental process-scoped IAST validation for exact-marker reachability.

  The first sensor action proves only that unchanged marker bytes reached a
  reviewed sink argument during one controlled in-process execution. It does
  not claim transformed-value propagation, cross-process taint, or
  exploitability.
  """

  @doc "Returns the sensor's versioned validation actions."
  @spec validation_actions() :: [Core.Validation.Action.t()]
  def validation_actions, do: Core.Validation.actions(RampartIAST.Validator)

  @doc "Validates one exact-marker reachability hypothesis under host-owned bindings."
  @spec validate(Core.Hypothesis.t(), keyword()) :: Core.Validation.Result.t()
  def validate(%Core.Hypothesis{} = hypothesis, opts) when is_list(opts) do
    request = Core.Validation.request(RampartIAST.Validator.action(), hypothesis)
    Core.Validation.run(RampartIAST.Validator, request, opts)
  end
end
