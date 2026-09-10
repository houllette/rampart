defmodule HavocProper.Sample do
  @moduledoc "Coverage, state-feature, and oracle data for one targeted-PBT candidate."

  @type line_id :: {module(), pos_integer()}
  @type feature_id :: String.t()
  @type t :: %__MODULE__{
          payload: term(),
          evaluation: {:ok, term()} | {:error, Havoc.Property.Failure.t()},
          covered_lines: [line_id()],
          features: [feature_id()],
          coverage_fitness: non_neg_integer(),
          feature_fitness: non_neg_integer(),
          fitness: number()
        }

  @enforce_keys [
    :payload,
    :evaluation,
    :covered_lines,
    :features,
    :coverage_fitness,
    :feature_fitness,
    :fitness
  ]
  defstruct [
    :payload,
    :evaluation,
    :covered_lines,
    :features,
    :coverage_fitness,
    :feature_fitness,
    :fitness
  ]
end
