defmodule RampartSAST.Observation do
  @moduledoc "A normalized deterministic rule signal; it is not a vulnerability verdict."

  alias RampartSAST.{Match, Source, Span}
  alias RampartSAST.Rule.Descriptor

  @type t :: %__MODULE__{
          id: String.t(),
          rule: Descriptor.t(),
          span: Span.t(),
          anchor: String.t(),
          occurrence: pos_integer(),
          message: String.t(),
          confidence: Core.Finding.confidence(),
          facts: map(),
          source_hash: String.t()
        }

  @enforce_keys [
    :id,
    :rule,
    :span,
    :anchor,
    :occurrence,
    :message,
    :confidence,
    :facts,
    :source_hash
  ]
  defstruct @enforce_keys

  @doc false
  @spec build(Descriptor.t(), Match.t(), source_hash :: String.t(), occurrence :: pos_integer()) ::
          t()
  def build(%Descriptor{} = descriptor, %Match{} = match, source_hash, occurrence)
      when is_integer(occurrence) and occurrence > 0 do
    %__MODULE__{
      id:
        Core.Finding.dedupe_id(:sast, [
          "observation",
          descriptor.id,
          match.span.file,
          match.anchor,
          occurrence
        ]),
      rule: descriptor,
      span: match.span,
      anchor: match.anchor,
      occurrence: occurrence,
      message: match.message,
      confidence: match.confidence || descriptor.confidence,
      facts: match.facts,
      source_hash: source_hash
    }
  end

  @doc "Projects an observation into bounded plain evidence data."
  @spec to_map(observation :: t()) :: map()
  def to_map(%__MODULE__{} = observation) do
    %{
      id: observation.id,
      rule: Descriptor.to_map(observation.rule),
      span: Span.to_map(observation.span),
      anchor: observation.anchor,
      occurrence: observation.occurrence,
      message: observation.message,
      confidence: observation.confidence,
      facts: observation.facts,
      source_hash: observation.source_hash,
      proof_level: :syntactic_match,
      exploitability: :not_evaluated
    }
  end

  @doc "Converts an observation and exact source snapshot into a Core finding."
  @spec to_finding(observation :: t(), source :: Source.t(), observed_at :: DateTime.t()) ::
          Core.Finding.t()
  def to_finding(%__MODULE__{} = observation, %Source{} = source, %DateTime{} = observed_at) do
    %Core.Finding{
      id: observation.id,
      source: :sast,
      category: observation.rule.category,
      locus: %{
        rule_id: observation.rule.id,
        file: observation.span.file,
        start_line: observation.span.start_line,
        start_column: observation.span.start_column,
        end_line: observation.span.end_line,
        end_column: observation.span.end_column,
        anchor: observation.anchor,
        occurrence: observation.occurrence,
        scope: observation.rule.scope,
        proof_level: :syntactic_match
      },
      severity: observation.rule.severity,
      confidence: observation.confidence,
      evidence: observation.message <> "; this is a syntactic match, not exploitability proof",
      raw: observation,
      seed: Source.seed(source, observation.rule.id),
      observed_at: observed_at
    }
  end
end
