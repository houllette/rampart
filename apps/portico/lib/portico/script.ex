defmodule Portico.Script do
  @moduledoc "Structured output from one NSE script."

  alias Portico.Script.Node

  @type t :: %__MODULE__{
          id: String.t() | nil,
          output: String.t() | nil,
          data: [Node.t()]
        }

  defstruct [:id, :output, data: []]
end
