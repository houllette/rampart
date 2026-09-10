defmodule RampartEvaluation.Fixture.Target do
  @moduledoc false

  alias RampartEvaluation.Fixture.Dependency
  alias RampartEvaluation.Fixture.Handler

  @behaviour Handler

  @impl true
  def command(value), do: Dependency.command(value)

  @impl true
  def ambiguous_command(value) do
    Dependency.command_ambiguous(value, rem(System.unique_integer(), 2) == 0)
  end

  @impl true
  def deserialize(value), do: Dependency.deserialize(value)

  @impl true
  def file_write(value), do: Dependency.file_write(value)

  def command_patched(value), do: Dependency.command_patched(value)

  def ambiguous_command_patched(value) do
    Dependency.command_ambiguous_patched(value, rem(System.unique_integer(), 2) == 0)
  end

  def deserialize_patched(value), do: Dependency.deserialize_patched(value)
  def file_write_patched(value), do: Dependency.file_write_patched(value)
end
