defmodule HavocProper.CoverageTest do
  use ExUnit.Case, async: false

  alias HavocProper.Coverage
  alias HavocProper.TestSupport.CoverageFixture

  test "measures a candidate's covered lines and restores the original BEAM" do
    beam_before = :code.which(CoverageFixture)

    {result, lines} =
      Coverage.with_modules([CoverageFixture], fn ->
        Coverage.measure([CoverageFixture], fn -> CoverageFixture.classify(950) end)
      end)

    assert result == :deep
    assert Enum.any?(lines, fn {module, _line} -> module == CoverageFixture end)
    assert :code.which(CoverageFixture) == beam_before
  end

  test "refuses to destroy an existing cover session" do
    :ok = start_cover()
    assert {:ok, CoverageFixture} = :cover.compile_beam(CoverageFixture)

    assert_raise ArgumentError, ~r/already instruments modules/, fn ->
      Coverage.with_modules([CoverageFixture], fn -> :unreachable end)
    end
  after
    :cover.stop()
  end

  defp start_cover do
    case :cover.start() do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end
  end
end
