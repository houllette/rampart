defmodule Portico.Discovery.Result do
  @moduledoc "A host and open ports emitted by a discovery engine."

  alias Portico.Target

  @type t :: %__MODULE__{
          target: Target.t() | nil,
          ip: String.t(),
          ports: [1..65_535],
          protocol: :tcp | :udp,
          meta: Portico.JSON.value()
        }

  @enforce_keys [:ip, :ports]
  defstruct [:target, :ip, protocol: :tcp, ports: [], meta: %{}]
end
