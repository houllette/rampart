defmodule MutationFixture.SecurityTest do
  use ExUnit.Case, async: true

  test "anonymous actors cannot read the secret" do
    assert MutationFixture.Controller.read(:anonymous) == :denied
    assert MutationFixture.Controller.read(:admin) == :secret
  end
end
