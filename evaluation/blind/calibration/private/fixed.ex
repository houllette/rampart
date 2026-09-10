defmodule BlindCalibration.RoutePolicy do
  @moduledoc false

  @protected_paths ["/admin/change-email", "/.well-known/admin/change-email"]

  def handle(%{"actor" => "admin", "path" => path}) when path in @protected_paths do
    %{status: 200, effect: :email_changed}
  end

  def handle(%{"path" => path}) when path in @protected_paths do
    %{status: 401, effect: :none}
  end

  def handle(_request), do: %{status: 404, effect: :none}
end
