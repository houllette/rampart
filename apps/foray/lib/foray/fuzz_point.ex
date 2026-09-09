defmodule Foray.FuzzPoint do
  @moduledoc "A named ffuf input position and its corpus source."

  @type location :: :url | :query | :header | :body | :cookie

  @type t :: %__MODULE__{
          keyword: String.t(),
          location: location(),
          name: String.t() | nil,
          wordlist_ref: String.t(),
          classes: [atom()]
        }

  @enforce_keys [:keyword, :location, :wordlist_ref]
  defstruct [:keyword, :location, :name, :wordlist_ref, classes: []]
end
