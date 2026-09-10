defmodule RampartEvaluation.Historical.PlugStaticFixed do
  @moduledoc false

  def invalid_path?([head | _tail]) when head in [".", "..", ""], do: true

  def invalid_path?([head | tail]) do
    String.contains?(head, ["/", "\\", ":", "\0"]) or invalid_path?(tail)
  end

  def invalid_path?([]), do: false
end
