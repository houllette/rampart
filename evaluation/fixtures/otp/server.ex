defmodule RampartEvaluation.OTP.Server do
  @moduledoc false
  use GenServer

  def start_link, do: GenServer.start_link(__MODULE__, :ok)
  def consume(server, value), do: GenServer.call(server, {:consume, value})

  @impl true
  def init(:ok), do: {:ok, %{}}

  @impl true
  def handle_call({:consume, value}, _from, state) do
    reply = System.cmd("printf", ["%s", value])
    {:reply, reply, state}
  end
end
