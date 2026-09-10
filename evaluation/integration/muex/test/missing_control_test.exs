defmodule MutationFixture.MissingControlTest do
  use ExUnit.Case, async: true

  test "admin happy path alone does not detect the bypass" do
    assert MutationFixture.Controller.read(:admin) == :secret
  end
end
