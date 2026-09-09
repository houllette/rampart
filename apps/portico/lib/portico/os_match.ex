defmodule Portico.OSMatch do
  @moduledoc "An operating-system fingerprint match."

  alias Portico.OSClass

  @type t :: %__MODULE__{
          name: String.t() | nil,
          accuracy: non_neg_integer() | nil,
          line: non_neg_integer() | nil,
          classes: [OSClass.t()]
        }

  defstruct [:name, :accuracy, :line, classes: []]
end
