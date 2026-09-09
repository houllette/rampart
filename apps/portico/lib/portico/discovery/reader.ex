defmodule Portico.Discovery.Reader do
  @moduledoc false

  alias Portico.Discovery.Cursor

  @spec start_link(pid(), Enumerable.t()) :: {:ok, pid()}
  def start_link(owner, enumerable) do
    pid = spawn_link(fn -> loop(owner, Cursor.new(enumerable)) end)
    {:ok, pid}
  end

  @spec demand(pid(), pos_integer()) :: :ok
  def demand(pid, amount) do
    send(pid, {:demand, amount})
    :ok
  end

  @spec stop(pid()) :: :ok
  def stop(pid) do
    send(pid, :stop)
    :ok
  end

  defp loop(owner, cursor) do
    receive do
      {:demand, amount} when is_integer(amount) and amount > 0 ->
        pull(owner, cursor, amount)

      :stop ->
        Cursor.halt(cursor)
    end
  end

  defp pull(owner, cursor, 0), do: loop(owner, cursor)

  defp pull(owner, cursor, remaining) do
    receive do
      :stop ->
        Cursor.halt(cursor)
    after
      0 ->
        case Cursor.next(cursor) do
          {:ok, item, cursor} ->
            send(owner, {__MODULE__, :item, self(), item})
            pull(owner, cursor, remaining - 1)

          :done ->
            send(owner, {__MODULE__, :done, self()})
        end
    end
  end
end
