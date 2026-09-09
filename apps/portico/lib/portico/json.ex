defmodule Portico.JSON do
  @moduledoc """
  Types shared by Portico's versioned serialization contract.

  Metadata supplied by callers and engines must contain JSON-compatible values.
  """

  @type value ::
          nil
          | boolean()
          | number()
          | String.t()
          | [value()]
          | %{optional(String.t() | atom()) => value()}
end
