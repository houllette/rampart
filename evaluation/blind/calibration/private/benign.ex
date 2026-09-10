defmodule BlindCalibration.RoutePolicy do
  @moduledoc false

  def handle(%{"actor" => "admin", "path" => "/admin/change-email"}) do
    %{status: 200, effect: :email_changed}
  end

  def handle(%{"path" => "/admin/change-email"}) do
    %{status: 401, effect: :none}
  end

  def handle(_request), do: %{status: 404, effect: :none}
end
