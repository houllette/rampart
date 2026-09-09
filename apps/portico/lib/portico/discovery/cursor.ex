defmodule Portico.Discovery.Cursor do
  @moduledoc false

  @type t ::
          {:new, Enumerable.t()}
          | {:continuation, (Enumerable.acc() -> Enumerable.result())}
          | :done

  @spec new(Enumerable.t()) :: t()
  def new(enumerable), do: {:new, enumerable}

  @spec next(t()) :: {:ok, term(), t()} | :done
  def next(:done), do: :done

  def next({:new, enumerable}) do
    enumerable
    |> Enumerable.reduce({:cont, nil}, &suspend/2)
    |> normalize()
  end

  def next({:continuation, continuation}) do
    continuation.({:cont, nil})
    |> normalize()
  end

  @spec halt(t()) :: :ok
  def halt({:continuation, continuation}) do
    _result = continuation.({:halt, nil})
    :ok
  end

  def halt(_cursor), do: :ok

  defp suspend(item, _acc), do: {:suspend, item}

  defp normalize({:suspended, item, continuation}) do
    {:ok, item, {:continuation, continuation}}
  end

  defp normalize({:done, _acc}), do: :done
  defp normalize({:halted, _acc}), do: :done
end
