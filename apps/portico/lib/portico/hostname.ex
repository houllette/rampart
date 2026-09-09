defmodule Portico.Hostname do
  @moduledoc "A hostname reported by an enrichment engine."

  @type t :: %__MODULE__{
          name: String.t() | nil,
          type: String.t() | nil
        }

  defstruct [:name, :type]
end
