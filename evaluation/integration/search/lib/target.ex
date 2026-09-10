defmodule SearchFixture.Target do
  @moduledoc false
  def run([?R, b, c, d]), do: second(b, c, d)
  def run(_value), do: %{status: 200, depth: 0}
  defp second(?A, c, d), do: third(c, d)
  defp second(_b, _c, _d), do: %{status: 200, depth: 1}
  defp third(?M, d), do: fourth(d)
  defp third(_c, _d), do: %{status: 200, depth: 2}
  defp fourth(?P), do: %{status: 500, depth: 4}
  defp fourth(_d), do: %{status: 200, depth: 3}
end
