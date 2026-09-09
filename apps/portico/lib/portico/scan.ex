defmodule Portico.Scan do
  @moduledoc "Immutable scan plan built by the high-level Portico API."

  alias Portico.Target

  defmodule Stage do
    @moduledoc "A validated engine module and its namespaced options."
    @type t :: %__MODULE__{engine: module(), opts: keyword()}
    defstruct [:engine, opts: []]
  end

  @type t :: %__MODULE__{
          id: String.t(),
          targets: [Target.t()],
          scope: Core.Scope.policy(),
          audit: Portico.Audit.hook() | nil,
          metadata: map(),
          discovery: Stage.t() | nil,
          enrichment: Stage.t() | nil,
          max_concurrency: pos_integer(),
          host_batch_size: pos_integer(),
          batch_timeout: non_neg_integer(),
          rate_limit: nil | %{allowed_messages: pos_integer(), interval: pos_integer()}
        }

  @enforce_keys [:id, :targets, :scope]
  defstruct [
    :id,
    :scope,
    :audit,
    :discovery,
    :enrichment,
    :rate_limit,
    targets: [],
    metadata: %{},
    max_concurrency: System.schedulers_online(),
    host_batch_size: 1,
    batch_timeout: 1_000
  ]
end
