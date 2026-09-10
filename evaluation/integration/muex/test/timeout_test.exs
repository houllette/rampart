defmodule MutationFixture.TimeoutTest do
  use ExUnit.Case, async: true

  test "anonymous callers never enter slow privileged execution" do
    assert MutationFixture.Slow.read(:anonymous) == :denied
  end
end
