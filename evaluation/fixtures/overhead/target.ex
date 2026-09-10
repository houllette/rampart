defmodule RampartEvaluation.Overhead.Sink do
  @moduledoc false

  def observe(value), do: value
end

defmodule RampartEvaluation.Overhead.Target do
  @moduledoc false

  alias RampartEvaluation.Overhead.Sink

  def run(marker) do
    Process.sleep(5)
    Sink.observe(marker)
  end
end
