defmodule BlindCalibration.RoutePolicy do
  @moduledoc false
  def handle(_request), do: raise("injected harness failure")
end
