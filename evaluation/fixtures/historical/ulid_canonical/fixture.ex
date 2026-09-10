defmodule RampartEvaluation.Historical.ULIDCanonical do
  @moduledoc false

  alias Havoc.Observation.Codec

  @alphabet "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
  @encoded_bytes 26
  @maximum_canonical_first_index 7

  def vulnerable(input) when is_binary(input) do
    case parse(input) do
      {:ok, first_index, rest} ->
        Codec.accepted(
          input,
          decoded_identity(first_index, rest),
          canonical_encoding(first_index, rest),
          %{codec: :reduced_ulid}
        )

      {:error, reason} ->
        Codec.rejected(input, reason, %{codec: :reduced_ulid})
    end
  end

  def fixed(input) when is_binary(input) do
    case parse(input) do
      {:ok, first_index, rest} when first_index <= @maximum_canonical_first_index ->
        Codec.accepted(
          input,
          decoded_identity(first_index, rest),
          canonical_encoding(first_index, rest),
          %{codec: :reduced_ulid}
        )

      {:ok, _first_index, _rest} ->
        Codec.rejected(input, :noncanonical_first_character, %{codec: :reduced_ulid})

      {:error, reason} ->
        Codec.rejected(input, reason, %{codec: :reduced_ulid})
    end
  end

  defp parse(input) when byte_size(input) == @encoded_bytes do
    <<first::binary-size(1), rest::binary>> = input

    case :binary.match(@alphabet, first) do
      {first_index, 1} -> {:ok, first_index, rest}
      :nomatch -> {:error, :invalid_alphabet}
    end
  end

  defp parse(_input), do: {:error, :invalid_length}

  defp decoded_identity(first_index, rest), do: {rem(first_index, 8), rest}

  defp canonical_encoding(first_index, rest) do
    canonical_first = binary_part(@alphabet, rem(first_index, 8), 1)
    canonical_first <> rest
  end
end
