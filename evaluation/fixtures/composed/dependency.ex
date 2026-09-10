defmodule RampartEvaluation.Fixture.Dependency do
  @moduledoc false

  def command(value), do: System.cmd("printf", ["%s", value])
  def command_patched(_value), do: System.cmd("printf", ["%s", "[fixed-command]"])

  def command_ambiguous(value, true), do: System.cmd("printf", ["%s", value])
  def command_ambiguous(value, false), do: System.cmd("printf", ["%s", value])

  def command_ambiguous_patched(_value, true),
    do: System.cmd("printf", ["%s", "[fixed-command-a]"])

  def command_ambiguous_patched(_value, false),
    do: System.cmd("printf", ["%s", "[fixed-command-b]"])

  def deserialize(value), do: :erlang.binary_to_term(value, [:safe])

  def deserialize_patched(_value) do
    :erlang.binary_to_term(:erlang.term_to_binary("[fixed-payload]"), [:safe])
  end

  def file_write(value) do
    path = temporary_path()

    try do
      File.write!(path, value)
    after
      File.rm(path)
    end
  end

  def file_write_patched(_value) do
    path = temporary_path()

    try do
      File.write!(path, "[fixed-file-content]")
    after
      File.rm(path)
    end
  end

  defp temporary_path do
    Path.join(
      System.tmp_dir!(),
      "rampart-evaluation-#{System.unique_integer([:positive, :monotonic])}.txt"
    )
  end
end
