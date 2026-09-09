defmodule Havoc.TestSupport.DerivedFunctionFixture do
  @moduledoc false

  @spec parse(String.t(), non_neg_integer()) :: {:ok, String.t()}
  def parse(value, _limit), do: {:ok, value}

  @spec decode(binary() | nil) :: binary() | nil
  def decode(value), do: value

  @spec count(integer()) :: integer()
  def count(value), do: value

  def undocumented(value), do: value
end
