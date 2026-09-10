defmodule RampartEvaluation.Fixture.Handler do
  @moduledoc false

  @callback command(binary()) :: term()
  @callback ambiguous_command(binary()) :: term()
  @callback deserialize(binary()) :: term()
  @callback file_write(binary()) :: term()
end
