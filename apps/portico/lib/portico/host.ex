defmodule Portico.Host do
  @moduledoc "The versioned, serializable result for one scanned host."

  alias Portico.{Hostname, OSMatch, Port, Script}

  @schema_version 1

  @type status :: :up | :down | :timeout | :error | :unknown

  @type t :: %__MODULE__{
          schema_version: pos_integer(),
          ip: String.t() | nil,
          hostname: String.t() | nil,
          hostnames: [Hostname.t()],
          status: status(),
          scanned_at: DateTime.t() | nil,
          addresses: %{optional(String.t()) => String.t()},
          ports: [Port.t()],
          scripts: [Script.t()],
          os_matches: [OSMatch.t()],
          meta: Portico.JSON.value()
        }

  defstruct schema_version: @schema_version,
            ip: nil,
            hostname: nil,
            hostnames: [],
            status: :unknown,
            scanned_at: nil,
            addresses: %{},
            ports: [],
            scripts: [],
            os_matches: [],
            meta: %{}

  @doc "Returns the current persisted result schema version."
  @spec schema_version() :: pos_integer()
  def schema_version, do: @schema_version
end
