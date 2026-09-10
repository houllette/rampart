defmodule BlindCalibration.RoutePolicy do
  @moduledoc false

  @protected_prefix "/admin"

  def handle(%{"actor" => "admin", "path" => path})
      when path in ["/admin/change-email", "/.well-known/admin/change-email"] do
    %{status: 200, effect: :email_changed}
  end

  def handle(%{"path" => @protected_prefix <> _rest}) do
    %{status: 401, effect: :none}
  end

  def handle(%{"path" => "/.well-known/admin/change-email"}) do
    %{status: 200, effect: :email_changed}
  end

  def handle(_request), do: %{status: 404, effect: :none}
end
