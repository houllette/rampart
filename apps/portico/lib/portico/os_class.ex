defmodule Portico.OSClass do
  @moduledoc "An operating-system class reported by nmap."

  @type t :: %__MODULE__{
          type: String.t() | nil,
          vendor: String.t() | nil,
          family: String.t() | nil,
          generation: String.t() | nil,
          accuracy: non_neg_integer() | nil,
          cpes: [String.t()]
        }

  defstruct [:type, :vendor, :family, :generation, :accuracy, cpes: []]
end
