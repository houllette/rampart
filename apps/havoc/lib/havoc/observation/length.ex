defmodule Havoc.Observation.Length do
  @moduledoc """
  A value observed at a caller-designated acceptance or downstream output boundary.

  Record the actual admitted value, including any transformation, rather than
  the validator's claimed length. The oracle measures it independently. The
  fixture owns evidence that the boundary was exercised and that the configured
  resource policy applies there; a grapheme-only UI policy is not a byte policy.
  """

  @type t :: %__MODULE__{
          input: term(),
          status: :accepted | :rejected,
          value: binary() | nil,
          reason: term(),
          metadata: map()
        }

  @enforce_keys [:input, :status]
  defstruct [:input, :status, :value, :reason, metadata: %{}]

  @doc "Records the exact input and the binary actually admitted at the boundary."
  @spec accepted(input :: term(), value :: binary(), metadata :: map()) :: t()
  def accepted(input, value, metadata \\ %{}) when is_binary(value) and is_map(metadata) do
    %__MODULE__{input: input, status: :accepted, value: value, metadata: metadata}
  end

  @doc "Records rejection before the value crossed the designated boundary."
  @spec rejected(input :: term(), reason :: term(), metadata :: map()) :: t()
  def rejected(input, reason, metadata \\ %{}) when is_map(metadata) do
    %__MODULE__{input: input, status: :rejected, reason: reason, metadata: metadata}
  end
end
