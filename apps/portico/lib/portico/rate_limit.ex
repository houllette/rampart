defmodule Portico.RateLimit do
  @moduledoc false

  @spec stream(Enumerable.t(), nil | %{allowed_messages: pos_integer(), interval: pos_integer()}) ::
          Enumerable.t()
  def stream(enumerable, nil), do: enumerable

  def stream(enumerable, %{allowed_messages: allowed, interval: interval}) do
    Stream.transform(enumerable, fn -> {System.monotonic_time(:millisecond), 0} end, fn item,
                                                                                        state ->
      {started_at, count} = wait_for_window(state, allowed, interval)
      {[item], {started_at, count + 1}}
    end)
  end

  defp wait_for_window({started_at, count}, allowed, _interval) when count < allowed do
    {started_at, count}
  end

  defp wait_for_window({started_at, _count}, _allowed, interval) do
    elapsed = System.monotonic_time(:millisecond) - started_at
    remaining = max(interval - elapsed, 0)

    if remaining > 0, do: Process.sleep(remaining)
    {System.monotonic_time(:millisecond), 0}
  end
end
