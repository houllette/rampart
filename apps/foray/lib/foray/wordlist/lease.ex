defmodule Foray.Wordlist.Lease do
  @moduledoc false

  use GenServer

  @spec start(directory :: Path.t()) :: {:ok, pid()} | {:error, term()}
  def start(directory), do: GenServer.start(__MODULE__, {self(), directory})

  @spec release(lease :: pid()) :: :ok
  def release(lease) do
    case GenServer.call(lease, :release) do
      {:ok, _paths} -> :ok
      {:error, reason, path} -> raise File.Error, reason: reason, path: path
    end
  end

  @impl true
  def init({owner, directory}) do
    monitor = Process.monitor(owner)
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    {:ok, %{monitor: monitor, directory: directory}}
  end

  @impl true
  def handle_call(:release, _from, state) do
    {:stop, :normal, File.rm_rf(state.directory), state}
  end

  @impl true
  def handle_info({:DOWN, monitor, :process, _pid, _reason}, %{monitor: monitor} = state) do
    case File.rm_rf(state.directory) do
      {:ok, _paths} -> {:stop, :normal, state}
      {:error, reason, path} -> raise File.Error, reason: reason, path: path
    end
  end
end
