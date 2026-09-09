defmodule Core.Finding do
  @moduledoc """
  Normalized cross-tool observation.

  A finding is an interchange projection, not a replacement for a tool's rich
  native domain model. `raw` deliberately remains an opaque tool-owned term.
  """

  @type severity :: :info | :low | :medium | :high | :critical | nil
  @type confidence :: :low | :medium | :high
  @type identity_part :: nil | boolean() | number() | String.t() | atom()

  @type t :: %__MODULE__{
          id: String.t() | nil,
          source: atom() | nil,
          category: atom() | nil,
          locus: %{optional(atom()) => term()} | nil,
          severity: severity(),
          confidence: confidence() | nil,
          evidence: String.t() | nil,
          raw: term(),
          seed: Core.Seed.t() | nil,
          observed_at: DateTime.t() | nil
        }

  defstruct [
    :id,
    :source,
    :category,
    :locus,
    :severity,
    :confidence,
    :evidence,
    :raw,
    :seed,
    :observed_at
  ]

  @doc """
  Returns a deterministic, source-scoped deduplication ID.

  Identity parts must be ordered stable scalars. Mutable enrichment such as a
  hostname, service name, product, or version should not be included.
  """
  @spec dedupe_id(source :: atom(), identity :: [identity_part()]) :: String.t()
  def dedupe_id(source, identity) when is_atom(source) and is_list(identity) do
    if Enum.all?(identity, &valid_identity_part?/1) do
      digest =
        {:security_core_finding_id, 1, source, identity}
        |> :erlang.term_to_binary([:deterministic])
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.encode16(case: :lower)

      Atom.to_string(source) <> ":" <> digest
    else
      raise ArgumentError, "finding identity must contain only stable scalar values"
    end
  end

  defp valid_identity_part?(part) do
    is_nil(part) or is_boolean(part) or is_number(part) or is_binary(part) or is_atom(part)
  end
end
