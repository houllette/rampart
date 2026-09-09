defmodule Portico.Service do
  @moduledoc "Structured service fingerprint data."

  @type t :: %__MODULE__{
          name: String.t() | nil,
          product: String.t() | nil,
          version: String.t() | nil,
          extra_info: String.t() | nil,
          tunnel: String.t() | nil,
          method: String.t() | nil,
          confidence: non_neg_integer() | nil,
          hostname: String.t() | nil,
          operating_system: String.t() | nil,
          device_type: String.t() | nil,
          rpc_number: String.t() | nil,
          cpes: [String.t()]
        }

  defstruct [
    :name,
    :product,
    :version,
    :extra_info,
    :tunnel,
    :method,
    :confidence,
    :hostname,
    :operating_system,
    :device_type,
    :rpc_number,
    cpes: []
  ]
end
