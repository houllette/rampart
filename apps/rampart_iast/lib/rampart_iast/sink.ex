defmodule RampartIAST.Sink do
  @moduledoc """
  A reviewed, versioned sink declaration used to configure targeted tracing.

  The declaration identifies one exact MFA and one or more one-based argument
  positions. It remains provider-owned rather than being accepted from a model
  or transcript.
  """

  @type sink_mfa :: {module(), atom(), arity()}

  @type t :: %__MODULE__{
          id: String.t(),
          schema_version: pos_integer(),
          context: atom(),
          mfa: sink_mfa(),
          argument_positions: [pos_integer()],
          category: atom(),
          sanitizer_expectations: [term()],
          severity: Core.Finding.severity(),
          rationale: String.t(),
          provenance: map()
        }

  @enforce_keys [
    :id,
    :schema_version,
    :context,
    :mfa,
    :argument_positions,
    :category,
    :sanitizer_expectations,
    :severity,
    :rationale,
    :provenance
  ]
  defstruct @enforce_keys

  @doc "Builds and validates a sink declaration."
  @spec new!(attributes :: keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [
        :id,
        :schema_version,
        :context,
        :mfa,
        :argument_positions,
        :category,
        :sanitizer_expectations,
        :severity,
        :rationale,
        :provenance
      ])

    attributes
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates a sink declaration and returns it."
  @spec validate!(sink :: t()) :: t()
  def validate!(%__MODULE__{} = sink) do
    valid? =
      Enum.all?([
        versioned_id?(sink.id),
        valid_schema_version?(sink.schema_version),
        named_atom?(sink.context),
        valid_mfa?(sink.mfa),
        valid_positions?(sink.argument_positions, sink.mfa),
        named_atom?(sink.category),
        is_list(sink.sanitizer_expectations),
        valid_severity?(sink.severity),
        nonempty_string?(sink.rationale),
        is_map(sink.provenance)
      ])

    if valid?, do: sink, else: raise(ArgumentError, "invalid IAST sink: #{inspect(sink)}")
  end

  defp valid_mfa?({module, function, arity}) do
    named_atom?(module) and named_atom?(function) and is_integer(arity) and arity >= 0
  end

  defp valid_mfa?(_mfa), do: false

  defp valid_positions?(positions, {_module, _function, arity}) do
    is_list(positions) and positions != [] and length(Enum.uniq(positions)) == length(positions) and
      Enum.all?(positions, &(is_integer(&1) and &1 > 0 and &1 <= arity))
  end

  defp valid_schema_version?(version), do: is_integer(version) and version > 0

  defp valid_severity?(severity),
    do: severity in [:info, :low, :medium, :high, :critical, nil]

  defp versioned_id?(value) do
    is_binary(value) and Regex.match?(~r/^[a-z0-9][a-z0-9._-]*\.v[1-9][0-9]*$/, value)
  end

  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
  defp named_atom?(value), do: is_atom(value) and value not in [nil, true, false]
end
