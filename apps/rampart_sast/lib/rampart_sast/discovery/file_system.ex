defmodule RampartSAST.Discovery.FileSystem do
  @moduledoc false

  @state_key {__MODULE__, :wildcard_state}

  @spec wildcard(Path.t(), String.t()) :: {[Path.t()], [Path.t()]}
  def wildcard(root, pattern) when is_binary(root) and is_binary(pattern) do
    previous_state = Process.get(@state_key)
    root = String.to_charlist(root)
    Process.put(@state_key, {root, []})

    try do
      matches =
        pattern
        |> String.to_charlist()
        |> :filelib.wildcard(root, __MODULE__)
        |> Enum.map(&List.to_string/1)

      {_root, blocked} = Process.get(@state_key)
      {matches, blocked |> Enum.uniq() |> Enum.map(&List.to_string/1)}
    after
      restore_state(previous_state)
    end
  end

  @doc false
  @spec list_dir(charlist()) :: {:ok, [charlist()]} | {:error, File.posix()}
  def list_dir(path) do
    case file_info(path) do
      {:ok, info} when elem(info, 2) == :directory ->
        :file.list_dir(path)

      {:ok, info} when elem(info, 2) == :symlink ->
        track_blocked(path)
        {:error, :enotdir}

      {:ok, _info} ->
        {:error, :enotdir}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc false
  @spec read_file_info(charlist()) :: {:ok, tuple()} | {:error, File.posix()}
  def read_file_info(path), do: file_info(path)

  @doc false
  @spec read_link_info(charlist()) :: {:ok, tuple()} | {:error, File.posix()}
  def read_link_info(path), do: :file.read_link_info(path)

  defp file_info(path) do
    case Process.get(@state_key) do
      {^path, _blocked} -> :file.read_file_info(path)
      {_root, _blocked} -> :file.read_link_info(path)
      nil -> {:error, :eperm}
    end
  end

  defp track_blocked(path) do
    case Process.get(@state_key) do
      {root, blocked} -> Process.put(@state_key, {root, [path | blocked]})
      nil -> :ok
    end
  end

  defp restore_state(nil), do: Process.delete(@state_key)
  defp restore_state(state), do: Process.put(@state_key, state)
end
