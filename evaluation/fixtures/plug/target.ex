defmodule RampartEvaluation.Plug.Handler do
  @moduledoc false

  @callback send_body(binary()) :: Plug.Conn.t()
end

defmodule RampartEvaluation.Plug.Target do
  @moduledoc false

  @behaviour RampartEvaluation.Plug.Handler

  @impl true
  def send_body(value) do
    Plug.Test.conn(:get, "/evaluation")
    |> Plug.Conn.send_resp(200, value)
  end

  def send_body_patched(_value) do
    Plug.Test.conn(:get, "/evaluation")
    |> Plug.Conn.send_resp(200, "[fixed-response]")
  end
end
