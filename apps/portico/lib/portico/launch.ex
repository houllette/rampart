defmodule Portico.Launch do
  @moduledoc false

  alias Portico.Audit

  @spec run(Portico.Scan.t(), [term()], term(), map(), (-> result)) :: result when result: term()
  def run(scan, authorization_targets, telemetry_target, metadata, launch_fun)
      when is_list(authorization_targets) and is_function(launch_fun, 0) do
    Core.Scope.ensure_all_authorized!(authorization_targets, scan.scope)
    Core.Telemetry.launch(:portico, telemetry_target)
    Audit.emit(scan.audit, :scanner_launch, metadata)
    launch_fun.()
  end
end
