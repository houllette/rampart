defmodule RampartIAST.StaticCandidate do
  @moduledoc """
  A reviewed, provider-owned static source-to-sink hypothesis candidate.

  A candidate preserves distinctions that broad program-dependence queries can
  blur: value versus control dependence, observed sanitizer nodes versus proven
  sanitization, and a unique versus ambiguous static sink location. None of
  these fields is a runtime verdict. `RampartIAST.Validator` remains the
  authority for exact-marker reachability.
  """

  alias RampartIAST.{SourceSpan, StaticProvenance}

  @type flow_basis :: :value_dependence | :control_dependence | :mixed_dependence | :unknown
  @type sanitizer_status :: :none_observed | :observed | :unknown
  @type localization ::
          :unique_static_call_site | :instrumented_call_site | :ambiguous | :unknown

  @type t :: %__MODULE__{
          id: String.t(),
          schema_version: pos_integer(),
          context: atom(),
          source_id: String.t(),
          sink_id: String.t(),
          source_sites: [SourceSpan.t()],
          sink_sites: [SourceSpan.t()],
          flow_basis: flow_basis(),
          sanitizer_status: sanitizer_status(),
          localization: localization(),
          provenance: StaticProvenance.t()
        }

  @enforce_keys [
    :id,
    :schema_version,
    :context,
    :source_id,
    :sink_id,
    :source_sites,
    :sink_sites,
    :flow_basis,
    :sanitizer_status,
    :localization,
    :provenance
  ]
  defstruct @enforce_keys

  @flow_bases [:value_dependence, :control_dependence, :mixed_dependence, :unknown]
  @sanitizer_statuses [:none_observed, :observed, :unknown]
  @localizations [:unique_static_call_site, :instrumented_call_site, :ambiguous, :unknown]
  @max_sites 32

  @doc "Builds and validates a reviewed static candidate."
  @spec new!(attributes :: keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [
        :id,
        :schema_version,
        :context,
        :source_id,
        :sink_id,
        :source_sites,
        :sink_sites,
        :flow_basis,
        :sanitizer_status,
        :localization,
        :provenance
      ])

    attributes
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates a reviewed static candidate and returns it."
  @spec validate!(candidate :: t()) :: t()
  def validate!(%__MODULE__{} = candidate) do
    valid? =
      Enum.all?([
        valid_identity?(candidate),
        valid_sites?(candidate.source_sites),
        valid_sites?(candidate.sink_sites),
        valid_analysis_qualifications?(candidate),
        valid_localization?(candidate),
        valid_provenance?(candidate.provenance)
      ])

    if valid?,
      do: candidate,
      else: raise(ArgumentError, "invalid IAST static candidate: #{inspect(candidate)}")
  end

  @doc "Returns a sink span only when the provider declares an accepted localization basis."
  @spec localized_sink_span(candidate :: t()) :: map() | nil
  def localized_sink_span(%__MODULE__{
        localization: localization,
        sink_sites: [%SourceSpan{} = span]
      })
      when localization in [:unique_static_call_site, :instrumented_call_site],
      do: SourceSpan.to_map(span)

  def localized_sink_span(%__MODULE__{}), do: nil

  @doc "Projects a candidate into bounded, transcript-safe evidence data."
  @spec to_map(candidate :: t()) :: map()
  def to_map(%__MODULE__{} = candidate) do
    %{
      id: candidate.id,
      schema_version: candidate.schema_version,
      context: candidate.context,
      source_id: candidate.source_id,
      sink_id: candidate.sink_id,
      source_sites: Enum.map(candidate.source_sites, &SourceSpan.to_map/1),
      sink_sites: Enum.map(candidate.sink_sites, &SourceSpan.to_map/1),
      flow_basis: candidate.flow_basis,
      sanitizer_status: candidate.sanitizer_status,
      localization: candidate.localization,
      provenance: StaticProvenance.to_map(candidate.provenance)
    }
  end

  defp valid_identity?(candidate) do
    versioned_id?(candidate.id) and positive_integer?(candidate.schema_version) and
      named_atom?(candidate.context) and nonempty_string?(candidate.source_id) and
      nonempty_string?(candidate.sink_id)
  end

  defp valid_analysis_qualifications?(candidate) do
    candidate.flow_basis in @flow_bases and
      candidate.sanitizer_status in @sanitizer_statuses and
      candidate.localization in @localizations
  end

  defp valid_sites?(sites) when is_list(sites) and sites != [] and length(sites) <= @max_sites do
    Enum.all?(sites, fn
      %SourceSpan{} = span -> SourceSpan.validate!(span) == span
      _other -> false
    end)
  rescue
    ArgumentError -> false
  end

  defp valid_sites?(_sites), do: false

  defp valid_localization?(%__MODULE__{
         localization: localization,
         sink_sites: [_one]
       })
       when localization in [:unique_static_call_site, :instrumented_call_site],
       do: true

  defp valid_localization?(%__MODULE__{localization: :ambiguous, sink_sites: sites}),
    do: length(sites) > 1

  defp valid_localization?(%__MODULE__{localization: :unknown}), do: true
  defp valid_localization?(_candidate), do: false

  defp valid_provenance?(%StaticProvenance{} = provenance) do
    StaticProvenance.validate!(provenance) == provenance
  rescue
    ArgumentError -> false
  end

  defp valid_provenance?(_provenance), do: false

  defp versioned_id?(value) do
    is_binary(value) and Regex.match?(~r/^[a-z0-9][a-z0-9._-]*\.v[1-9][0-9]*$/, value)
  end

  defp positive_integer?(value), do: is_integer(value) and value > 0
  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
end
