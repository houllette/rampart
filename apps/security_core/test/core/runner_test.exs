defmodule Core.TestRunner do
  @behaviour Core.Runner

  @impl true
  def stream(argv, opts), do: [argv, opts]

  @impl true
  def run(argv, opts), do: {inspect({argv, opts}), 17}
end

defmodule Core.RunnerTest do
  use ExUnit.Case, async: true

  alias Core.Runner

  test "dispatches stream and run through an explicit backend" do
    assert [["scanner", "--json"], [format: :chunks]] =
             Runner.stream(["scanner", "--json"], backend: Core.TestRunner, format: :chunks)

    assert {output, 17} = Runner.run(["scanner", "--version"], backend: Core.TestRunner)
    assert output =~ "scanner"
  end
end
