defmodule Foray.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Registry, keys: :unique, name: Foray.Registry},
      {Task.Supervisor, name: Foray.TaskSupervisor}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Foray.Supervisor)
  end
end
