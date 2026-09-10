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

  test "restores instrumented code when the caller is killed" do
    parent = self()
    beam = :code.which(CoverageFixture)

    owner =
      Task.async(fn ->
        Coverage.with_modules([CoverageFixture], fn ->
          send(parent, :instrumented)
          Process.sleep(:infinity)
        end)
      end)

    assert_receive :instrumented, 2_000
    Task.shutdown(owner, :brutal_kill)
    assert eventually(fn -> :code.which(CoverageFixture) == beam end)

    assert :deep =
             Coverage.with_modules([CoverageFixture], fn -> CoverageFixture.classify(950) end)
  end

  test "nested use refuses the active session without deadlocking or destroying it" do
    assert :deep =
             Coverage.with_modules([CoverageFixture], fn ->
               assert_raise ArgumentError, ~r/already instruments modules/, fn ->
                 Coverage.with_modules([CoverageFixture], fn -> :unreachable end)
               end

               CoverageFixture.classify(950)
             end)
  end

  defp eventually(predicate, attempts \\ 100)
  defp eventually(_predicate, 0), do: false

  defp eventually(predicate, attempts) do
    if predicate.() do
      true
    else
      Process.sleep(20)
      eventually(predicate, attempts - 1)
    end
  end

  defp start_cover do
    case :cover.start() do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _pid}} -> :ok
    end
  end

  test "serializes overlapping callers and restores code after an exception" do
    caller = self()
    beam = :code.which(CoverageFixture)

    first =
      Task.async(fn ->
        Coverage.with_modules([CoverageFixture], fn ->
          send(caller, :first_entered)

          receive do
            :release ->
              Coverage.measure([CoverageFixture], fn -> CoverageFixture.classify(950) end)
          end
        end)
      end)

    assert_receive :first_entered, 2_000

    second =
      Task.async(fn ->
        assert_raise RuntimeError, "controlled failure", fn ->
          Coverage.with_modules([CoverageFixture], fn ->
            send(caller, :second_entered)
            raise "controlled failure"
          end)
        end
      end)

    refute_receive :second_entered, 100
    send(first.pid, :release)
    assert {:deep, [_ | _]} = Task.await(first)
    assert_receive :second_entered, 3_000
    assert %RuntimeError{} = Task.await(second)
    assert :code.which(CoverageFixture) == beam
  end
end
