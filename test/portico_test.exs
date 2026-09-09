defmodule PorticoTest do
  use ExUnit.Case
  doctest Portico

  test "greets the world" do
    assert Portico.hello() == :world
  end
end
