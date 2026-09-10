defmodule RampartEvaluation.OTP.Target do
  @moduledoc false

  alias RampartEvaluation.OTP.Server

  def run(value) do
    {:ok, server} = Server.start_link()

    try do
      Server.consume(server, value)
    after
      GenServer.stop(server)
    end
  end
end
