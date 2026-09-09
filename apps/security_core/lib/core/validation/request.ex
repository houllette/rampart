defmodule Core.Validation.Request do
  @moduledoc "A concrete invocation of a discoverable validation action."

  alias Core.Validation.Action

  @type subject :: Core.Finding.t() | Core.Seed.t() | Core.Hypothesis.t()

  @type t :: %__MODULE__{
          id: String.t(),
          action: Action.t(),
          subject: subject(),
          context: map(),
          meta: map()
        }

  @enforce_keys [:id, :action, :subject]
  defstruct [:id, :action, :subject, context: %{}, meta: %{}]
end
