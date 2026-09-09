defmodule Foray.Scan do
  @moduledoc "Immutable multi-target web-fuzzing plan built by the high-level API."

  alias Foray.{FuzzPoint, Oracle, Target, Wordlist}

  defmodule Engine do
    @moduledoc "A validated fuzz engine and its namespaced options."
    @type t :: %__MODULE__{module: module(), opts: keyword()}
    defstruct [:module, opts: []]
  end

  @type t :: %__MODULE__{
          id: String.t(),
          targets: [Target.t()],
          scope: Core.Scope.policy(),
          audit: Foray.Audit.hook() | nil,
          metadata: map(),
          fuzz_points: [FuzzPoint.t()],
          wordlists: [Wordlist.t()],
          oracle: Oracle.t(),
          mode: :clusterbomb | :pitchfork | :sniper,
          method: String.t(),
          headers: %{optional(String.t()) => String.t()},
          body: String.t() | nil,
          cookies: String.t() | nil,
          aggregate_rate: pos_integer(),
          threads: pos_integer(),
          delay: String.t() | nil,
          max_time: pos_integer(),
          max_concurrency: pos_integer(),
          job_rate_limit: nil | %{allowed_messages: pos_integer(), interval: pos_integer()},
          recursion: nil | %{depth: pos_integer(), strategy: :default | :greedy},
          engine: Engine.t()
        }

  @enforce_keys [:id, :targets, :scope, :engine]
  defstruct [
    :id,
    :scope,
    :audit,
    :body,
    :cookies,
    :delay,
    :job_rate_limit,
    :recursion,
    targets: [],
    metadata: %{},
    fuzz_points: [],
    wordlists: [],
    oracle: nil,
    mode: :clusterbomb,
    method: "GET",
    headers: %{},
    aggregate_rate: 50,
    threads: 20,
    max_time: 300,
    max_concurrency: 2,
    engine: nil
  ]
end
