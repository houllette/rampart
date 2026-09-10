defmodule Foray.Job do
  @moduledoc "One bounded ffuf invocation. Foray orchestrates jobs, never individual requests."

  alias Foray.{FuzzPoint, Oracle, Target, Wordlist}

  @type t :: %__MODULE__{
          id: String.t(),
          target: Target.t(),
          method: String.t(),
          headers: %{optional(String.t()) => String.t()},
          body: String.t() | nil,
          cookies: String.t() | nil,
          fuzz_points: [FuzzPoint.t()],
          wordlists: [Wordlist.t()],
          seed_index: nil | [{String.t(), map()}],
          oracle: Oracle.t(),
          mode: :clusterbomb | :pitchfork | :sniper,
          threads: pos_integer(),
          request_rate: pos_integer(),
          delay: String.t() | nil,
          max_time: pos_integer(),
          recursion: nil | %{depth: pos_integer(), strategy: :default | :greedy},
          meta: map()
        }

  @enforce_keys [
    :id,
    :target,
    :method,
    :fuzz_points,
    :wordlists,
    :oracle,
    :mode,
    :threads,
    :request_rate,
    :max_time
  ]
  defstruct [
    :id,
    :target,
    :body,
    :cookies,
    :delay,
    :recursion,
    :seed_index,
    method: "GET",
    headers: %{},
    fuzz_points: [],
    wordlists: [],
    oracle: nil,
    mode: :clusterbomb,
    threads: 20,
    request_rate: 25,
    max_time: 300,
    meta: %{}
  ]
end
