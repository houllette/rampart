defmodule Portico.Port do
  @moduledoc "A network port and its enrichment data."

  alias Portico.{Script, Service}

  @type t :: %__MODULE__{
          number: 1..65_535 | nil,
          protocol: :tcp | :udp | String.t() | nil,
          state: String.t() | nil,
          reason: String.t() | nil,
          service: Service.t() | nil,
          scripts: [Script.t()],
          meta: Portico.JSON.value()
        }

  defstruct [:number, :protocol, :state, :reason, :service, scripts: [], meta: %{}]
end
