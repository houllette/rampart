defmodule Core.Scope do
  @moduledoc "Fail-closed policy dispatch and guarded-launch helpers."

  alias Core.Scope.Error

  @type policy :: term()

  @doc "Returns whether a policy explicitly authorizes a target."
  @spec authorized?(target :: term(), policy()) :: boolean()
  def authorized?(_target, nil), do: false

  def authorized?(target, policy) when is_function(policy, 1) do
    policy.(target) == true
  end

  def authorized?(target, policy) when is_function(policy, 2) do
    policy.(target, nil) == true
  end

  def authorized?(target, %module{} = state) do
    call_policy(module, target, state)
  end

  def authorized?(target, {module, state}) when is_atom(module) do
    call_policy(module, target, state)
  end

  def authorized?(target, module) when is_atom(module) do
    call_policy(module, target, nil)
  end

  def authorized?(_target, _policy), do: false

  @doc "Returns `:ok` for an authorized target or raises `Core.Scope.Error`."
  @spec ensure_authorized!(target :: term(), policy()) :: :ok
  def ensure_authorized!(target, policy) do
    if authorized?(target, policy) do
      :ok
    else
      raise Error, target: target
    end
  end

  @doc "Authorizes every target before returning, so callers cannot partially launch a collection."
  @spec ensure_all_authorized!(targets :: [term()], policy()) :: :ok
  def ensure_all_authorized!(targets, policy) when is_list(targets) do
    Enum.each(targets, &ensure_authorized!(&1, policy))
  end

  @doc "Authorizes one target, emits the shared launch audit event, then invokes the launch function."
  @spec guarded_launch(tool :: atom(), target :: term(), policy(), (-> result)) :: result
        when result: term()
  def guarded_launch(tool, target, policy, launch_fun) when is_function(launch_fun, 0) do
    ensure_authorized!(target, policy)
    Core.Telemetry.launch(tool, target)
    launch_fun.()
  end

  defp call_policy(module, target, state) do
    if Code.ensure_loaded?(module) and function_exported?(module, :authorized?, 2) do
      module.authorized?(target, state) == true
    else
      false
    end
  end
end
