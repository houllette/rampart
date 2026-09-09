defmodule HavocProper.Gen do
  @moduledoc """
  PropEr generators with explicit neighbourhood functions for targeted search.

  These are intentionally separate from `Havoc.Gen`, whose public generators
  remain StreamData generators. The adapter's binary neighbourhood also avoids
  relying on PropEr 1.5's default binary targeted-generation path, which is
  incompatible with some current OTP releases.
  """

  @default_bytes [0, ?%, ?&, ?', ?", ?/, ?<, ?>, ??, ?A, ?Z, ?a, ?z, ?0, ?9]

  @doc "Builds a bounded binary PropEr type with a targeted-search neighbourhood."
  @spec binary(opts :: keyword()) :: PropCheck.type()
  def binary(opts \\ []) do
    schema = [
      max_length: [type: :pos_integer, default: 256],
      mutation_bytes: [type: {:list, :non_neg_integer}, default: @default_bytes]
    ]

    opts = NimbleOptions.validate!(opts, schema)
    max_length = opts[:max_length]
    bytes = validate_bytes!(opts[:mutation_bytes])
    base = PropCheck.BasicTypes.resize(max_length, PropCheck.BasicTypes.binary())
    :proper_gen_next.set_user_nf(base, neighbourhood(max_length, bytes))
  end

  @doc "Builds a targeted PropEr type from Havoc's curated injection classes."
  @spec injection([atom()], opts :: keyword()) :: PropCheck.type()
  def injection(classes, opts \\ []) when is_list(classes) do
    schema = [max_length: [type: :pos_integer, default: 1_024]]
    opts = NimbleOptions.validate!(opts, schema)

    values =
      classes
      |> Enum.flat_map(&Havoc.Corpus.builtin/1)
      |> Enum.map(& &1.value)
      |> Enum.filter(&is_binary/1)
      |> Enum.uniq()

    case values do
      [] ->
        raise ArgumentError, "at least one binary payload is required"

      _ ->
        base = PropCheck.BasicTypes.elements(values)
        :proper_gen_next.set_user_nf(base, neighbourhood(opts[:max_length], @default_bytes))
    end
  end

  defp neighbourhood(max_length, bytes) do
    fn previous, {_depth, temperature} ->
      previous
      |> mutations(bytes, max_length, temperature)
      |> PropCheck.BasicTypes.elements()
    end
  end

  defp mutations(previous, bytes, max_length, temperature) when is_binary(previous) do
    stride = max(1, trunc(max(temperature, 0.01) * max(byte_size(previous), 1)))

    replacements =
      if byte_size(previous) == 0 do
        []
      else
        index = rem(stride, byte_size(previous))
        Enum.map(bytes, &replace_byte(previous, index, &1))
      end

    additions =
      if byte_size(previous) < max_length do
        Enum.flat_map(bytes, fn byte -> [previous <> <<byte>>, <<byte>> <> previous] end)
      else
        []
      end

    deletions =
      if byte_size(previous) > 0 do
        [
          binary_part(previous, 0, byte_size(previous) - 1),
          binary_part(previous, 1, byte_size(previous) - 1)
        ]
      else
        []
      end

    [previous | replacements ++ additions ++ deletions]
    |> Enum.map(&binary_part(&1, 0, min(byte_size(&1), max_length)))
    |> Enum.uniq()
  end

  defp replace_byte(binary, index, byte) do
    <<prefix::binary-size(^index), _old, suffix::binary>> = binary
    prefix <> <<byte>> <> suffix
  end

  defp validate_bytes!(bytes) do
    if Enum.all?(bytes, &(&1 in 0..255)) and bytes != [] do
      Enum.uniq(bytes)
    else
      raise ArgumentError, "mutation_bytes must be a non-empty list of bytes"
    end
  end
end
