defmodule Havoc.Oracle.Violation do
  @moduledoc "A structured security-oracle failure before it is projected into a Core finding."

  @type t :: %__MODULE__{
          oracle: atom(),
          category: atom(),
          confidence: Core.Finding.confidence(),
          evidence: String.t(),
          details: map()
        }

  @enforce_keys [:oracle, :category, :confidence, :evidence]
  defstruct [:oracle, :category, :confidence, :evidence, details: %{}]
end
