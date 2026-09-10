defmodule Havoc.Observation.Codec do
  @moduledoc "A normalized accepted/rejected codec observation for relational security oracles."

  @type status :: :accepted | :rejected
  @type t :: %__MODULE__{
          input: term(),
          status: status(),
          decoded: term(),
          reencoded: term(),
          reason: term(),
          metadata: map()
        }

  @enforce_keys [:input, :status, :metadata]
  defstruct [:input, :status, :decoded, :reencoded, :reason, metadata: %{}]

  @doc "Records an accepted input, its decoded identity, and its canonical re-encoding."
  @spec accepted(input :: term(), decoded :: term(), reencoded :: term(), metadata :: map()) ::
          t()
  def accepted(input, decoded, reencoded, metadata \\ %{}) when is_map(metadata) do
    %__MODULE__{
      input: input,
      status: :accepted,
      decoded: decoded,
      reencoded: reencoded,
      metadata: metadata
    }
  end

  @doc "Records that a codec rejected an input before producing an identity."
  @spec rejected(input :: term(), reason :: term(), metadata :: map()) :: t()
  def rejected(input, reason, metadata \\ %{}) when is_map(metadata) do
    %__MODULE__{input: input, status: :rejected, reason: reason, metadata: metadata}
  end
end
