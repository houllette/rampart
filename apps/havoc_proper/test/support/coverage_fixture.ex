defmodule HavocProper.TestSupport.CoverageFixture do
  @moduledoc false

  def classify(value) do
    cond do
      value >= 900 ->
        :deep

      value >= 100 ->
        :middle

      true ->
        :shallow
    end
  end

  def bytes(value) when is_binary(value) do
    if String.contains?(value, "HAVOC") do
      :marker
    else
      :plain
    end
  end
end
