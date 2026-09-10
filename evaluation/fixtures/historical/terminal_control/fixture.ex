defmodule RampartEvaluation.Historical.TerminalControl do
  @moduledoc false

  @control_characters ~r/[[:cntrl:]]/u

  def vulnerable(metadata) when is_binary(metadata) do
    rendered = "Package: #{metadata}\n"
    rendered
  end

  def fixed(metadata) when is_binary(metadata) do
    metadata = String.replace(metadata, @control_characters, "")
    rendered = "Package: #{metadata}\n"
    rendered
  end
end
