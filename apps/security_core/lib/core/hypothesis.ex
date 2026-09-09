defmodule Core.Hypothesis do
  @moduledoc """
  A structured claim that a Rampart validation action can confirm or refute.

  Findings and seeds can be validated directly. This type exists for claims
  that have not yet become findings, especially IAST claims such as "request
  parameter `q` reaches `:erlang.binary_to_term/1`".

  `locus` is deliberately source-shaped for the same reason as
  `Core.Finding.locus`: Phoenix, Nerves, library, and bare-OTP contexts do not
  share one useful location shape.
  """

  @type t :: %__MODULE__{
          id: String.t(),
          source: atom(),
          kind: atom(),
          claim: String.t(),
          locus: %{optional(atom()) => term()},
          finding: Core.Finding.t() | nil,
          seed: Core.Seed.t() | nil,
          meta: map()
        }

  @enforce_keys [:id, :source, :kind, :claim]
  defstruct [:id, :source, :kind, :claim, :finding, :seed, locus: %{}, meta: %{}]
end
