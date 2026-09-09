defmodule Havoc.Finding do
  @moduledoc "Projects final, shrunk oracle violations into Core findings and counterexample seeds."

  alias Core.{Finding, Seed}
  alias Havoc.{Oracle.Violation, TermCodec}

  @doc "Builds the normalized finding and durable seed for one evaluated oracle violation."
  @spec from_violation(Violation.t(), payload :: term(), observation :: term(), config :: map()) ::
          {Finding.t(), Seed.t()}
  def from_violation(%Violation{} = violation, payload, observation, config) do
    locus = normalized_locus(config)

    finding_id =
      Finding.dedupe_id(:havoc, [
        "property_violation",
        config.property_id,
        violation.oracle,
        violation.category,
        TermCodec.fingerprint(locus)
      ])

    seed = %Seed{
      id:
        Finding.dedupe_id(:havoc, [
          "counterexample",
          config.property_id,
          violation.oracle,
          TermCodec.fingerprint(payload)
        ]),
      value: payload,
      classes: Enum.uniq(config.classes ++ [violation.oracle, violation.category]),
      provenance: :counterexample,
      origin: {:havoc, finding_id},
      meta: %{
        property_id: config.property_id,
        property_name: config.property_name,
        oracle: violation.oracle,
        locus: locus
      }
    }

    finding = %Finding{
      id: finding_id,
      source: :havoc,
      category: violation.category,
      locus: locus,
      severity: nil,
      confidence: violation.confidence,
      evidence: violation.evidence,
      raw: %{
        property_id: config.property_id,
        payload: payload,
        observation: observation,
        oracle: violation.oracle,
        details: violation.details
      },
      seed: seed,
      observed_at: DateTime.utc_now()
    }

    {finding, seed}
  end

  defp normalized_locus(config) do
    defaults = %{
      module: config.module |> Atom.to_string() |> String.trim_leading("Elixir."),
      property: config.property_name
    }

    Map.merge(defaults, config.locus)
  end
end
