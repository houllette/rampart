defmodule Portico.Scope.CIDR do
  @moduledoc false

  import Bitwise, only: [bsl: 2, band: 2]

  alias Portico.Target

  @spec contains?(Target.t(), Target.t()) :: boolean()
  def contains?(
        %Target{address: allowed, prefix: allowed_prefix, bits: bits},
        %Target{address: candidate, prefix: candidate_prefix, bits: bits}
      )
      when not is_nil(allowed) and not is_nil(candidate) and candidate_prefix >= allowed_prefix do
    mask = mask(bits, allowed_prefix)
    band(to_integer(allowed), mask) == band(to_integer(candidate), mask)
  end

  def contains?(_allowed, _candidate), do: false

  defp mask(_bits, 0), do: 0
  defp mask(bits, prefix), do: bsl(bsl(1, prefix) - 1, bits - prefix)

  defp to_integer(address) when tuple_size(address) == 4 do
    address
    |> Tuple.to_list()
    |> Enum.reduce(0, fn part, acc -> bsl(acc, 8) + part end)
  end

  defp to_integer(address) when tuple_size(address) == 8 do
    address
    |> Tuple.to_list()
    |> Enum.reduce(0, fn part, acc -> bsl(acc, 16) + part end)
  end
end
