defmodule Havoc.ResourceContractTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Core.Validation.Wire
  alias Havoc.Observation.{Incremental, Length}
  alias Havoc.Oracle

  test "length policies measure the accepted boundary value in the declared unit" do
    input = "a" <> String.duplicate("\u0301", 4)
    observation = Length.accepted(input, input)

    assert verdict(observation, input, Oracle.bounded_length(unit: :bytes, max_length: 4)) ==
             :confirmed

    assert verdict(observation, input, Oracle.bounded_length(unit: :codepoints, max_length: 4)) ==
             :confirmed

    assert verdict(observation, input, Oracle.bounded_length(unit: :graphemes, max_length: 1)) ==
             :refuted

    assert verdict(Length.accepted(input, "a"), input, length_oracle()) == :refuted
    assert verdict(Length.rejected(input, :too_long), input, length_oracle()) == :refuted
  end

  test "length controls include exact boundaries and unavailable Unicode measurements" do
    for size <- [3, 4, 5] do
      input = String.duplicate("a", size)
      expected = if size > 4, do: :confirmed, else: :refuted
      assert verdict(Length.accepted(input, input), input, length_oracle()) == expected
    end

    invalid = <<255, 255, 255, 255, 255>>
    assert verdict(Length.accepted(invalid, invalid), invalid, length_oracle()) == :confirmed

    unicode = Oracle.bounded_length(unit: :codepoints, max_length: 1, max_measurement_bytes: 4)
    assert verdict(Length.accepted(invalid, invalid), invalid, unicode) == :inconclusive
    assert verdict(Length.accepted("é", "é"), "é", unicode) == :refuted
    assert verdict(Length.accepted("abcde", "abcde"), "abcde", unicode) == :inconclusive
    assert verdict(Length.accepted("other", "aaaaa"), "input", length_oracle()) == :inconclusive
    assert verdict(%{}, "input", length_oracle()) == :inconclusive
  end

  test "incremental budgets check intermediate states even if the final state is empty" do
    chunks = ["aaaaa", "\n"]
    trace = capture(chunks)

    assert Enum.map(trace.samples, & &1.retained_bytes) == [0, 5, 0]
    assert Enum.map(trace.samples, & &1.work) == [0, 5, 6]
    assert trace.status == :accepted
    assert trace.delivered_chunks == 2
    assert verdict(trace, chunks, buffer_oracle()) == :confirmed
    assert verdict(trace, chunks, work_oracle(5)) == :confirmed
    assert verdict(trace, chunks, work_oracle(6)) == :refuted
    assert verdict(capture(["aaaa", "\n"]), ["aaaa", "\n"], buffer_oracle()) == :refuted
  end

  test "missing metrics, mismatched units and absent execution stay inconclusive" do
    chunks = ["abc"]
    trace = Incremental.capture(chunks, nil, fn _, _ -> {:incomplete, nil} end, fn _ -> %{} end)

    assert verdict(trace, chunks, buffer_oracle()) == :inconclusive
    assert verdict(trace, chunks, work_oracle(4)) == :inconclusive

    assert verdict(
             capture(chunks),
             chunks,
             Oracle.incremental_work_budget(unit: :reductions, max_work: 4)
           ) ==
             :inconclusive

    assert verdict(capture([]), [], buffer_oracle()) == :inconclusive
    assert verdict(capture(chunks), ["different"], buffer_oracle()) == :inconclusive
  end

  test "the driver stops at rejection and never delivers remaining chunks" do
    trace =
      Incremental.capture(
        ["bad", "never delivered"],
        0,
        fn chunk, _ ->
          assert chunk == "bad"
          {:rejected, 1}
        end,
        fn count -> %{retained_bytes: 0, work: count} end,
        work_unit: :steps
      )

    assert trace.status == :rejected
    assert trace.delivered_chunks == 1
    assert List.last(trace.samples).work == 1
  end

  test "input caps are checked before invoking either callback" do
    step = fn _, _ -> flunk("step must not run") end
    measure = fn _ -> flunk("measurement must not run") end

    for {chunks, options} <- [
          {["abc"], [max_input_bytes: 2]},
          {["a", "b"], [max_chunks: 1]},
          {["a", :invalid], []},
          {[""], []}
        ] do
      assert_raise ArgumentError, fn ->
        Incremental.capture(chunks, nil, step, measure, options)
      end
    end
  end

  test "invalid measurements and decreasing work counters are harness errors" do
    assert_raise ArgumentError, fn ->
      Incremental.capture(
        ["a"],
        1,
        fn _, _ -> {:incomplete, 0} end,
        fn n -> %{retained_bytes: 0, work: n} end,
        work_unit: :steps
      )
    end

    assert_raise ArgumentError, fn ->
      Incremental.capture(["a"], nil, fn _, _ -> {:incomplete, nil} end, fn _ ->
        %{retained_bytes: -1}
      end)
    end
  end

  test "a missing intermediate measurement cannot refute, or conceal an observed violation" do
    chunks = ["a", "b"]
    step = fn _, count -> {:incomplete, count + 1} end

    trace =
      Incremental.capture(
        chunks,
        0,
        step,
        fn
          1 -> %{}
          n -> %{retained_bytes: n, work: n}
        end,
        work_unit: :steps
      )

    assert verdict(trace, chunks, Oracle.incremental_work_budget(unit: :steps, max_work: 2)) ==
             :inconclusive

    assert verdict(trace, chunks, Oracle.incremental_work_budget(unit: :steps, max_work: 1)) ==
             :confirmed

    assert verdict(trace, chunks, Oracle.incremental_buffer_budget(max_bytes: 2)) == :inconclusive
    assert verdict(trace, chunks, Oracle.incremental_buffer_budget(max_bytes: 1)) == :confirmed

    assert_raise ArgumentError, "incremental work counter decreased", fn ->
      Incremental.capture(
        chunks,
        0,
        step,
        fn
          0 -> %{work: 5}
          1 -> %{}
          2 -> %{work: 4}
        end,
        work_unit: :steps
      )
    end
  end

  test "resource contracts require explicit policy units and valid limits" do
    assert_raise NimbleOptions.ValidationError, fn -> Oracle.bounded_length(max_length: 4) end

    assert_raise NimbleOptions.ValidationError, fn ->
      Oracle.bounded_length(unit: :characters, max_length: 4)
    end

    assert_raise NimbleOptions.ValidationError, fn ->
      Oracle.incremental_buffer_budget(max_bytes: -1)
    end

    assert_raise ArgumentError, fn -> Oracle.incremental_work_budget(unit: nil, max_work: 1) end
  end

  test "malformed externally assembled counter observations cannot refute a budget" do
    chunks = ["abc"]
    trace = capture(chunks)

    for unknown <- [:unknown, -1, 1.5] do
      samples = Enum.map(trace.samples, &%{&1 | retained_bytes: unknown})
      assert verdict(%{trace | samples: samples}, chunks, buffer_oracle()) == :inconclusive
    end
  end

  test "a concrete byte partition persists and replays with bounded JSON evidence" do
    path =
      Path.join(System.tmp_dir!(), "havoc-resource-#{System.unique_integer([:positive])}.json")

    on_exit(fn -> File.rm(path) end)
    chunks = [<<255, 255, 255>>, <<255, 255>>]
    seed = %Core.Seed{id: "partition-replay", value: chunks, provenance: :generated}
    options = [oracles: [buffer_oracle()], corpus_path: path, property_id: "resource:replay"]

    assert %{verdict: :confirmed, findings: [finding]} = Havoc.validate(seed, &capture/1, options)
    assert finding.category == :resource_exhaustion
    assert [saved] = Havoc.Corpus.load(path: path)
    assert saved.value === chunks

    result = Havoc.validate(saved, &capture/1, options)
    assert result.verdict == :confirmed
    assert result.seed.value === chunks
    wire = result |> Wire.result() |> Wire.encode!()
    assert byte_size(wire) < 8_192
    assert wire =~ "measured 5 bytes"
    assert wire =~ "limit 4 at sample 2"
    refute Map.has_key?(Wire.result(result)["evidence"], "raw")
  end

  property "Unicode generation obeys its byte budget, including shrunk values" do
    check all max_bytes <- StreamData.integer(1..64),
              value <- Havoc.Gen.unicode_length(max_bytes: max_bytes, max_marks: 64) do
      assert String.valid?(value)
      assert byte_size(value) <= max_bytes
    end
  end

  property "partitions preserve arbitrary bytes and bound delivery count" do
    check all input <- StreamData.binary(max_length: 64),
              max_chunks <- StreamData.integer(1..8),
              chunks <- Havoc.Gen.byte_partitions(input, max_chunks: max_chunks) do
      assert IO.iodata_to_binary(chunks) == input
      assert length(chunks) <= max_chunks
      assert Enum.all?(chunks, &(byte_size(&1) > 0))
    end
  end

  test "partition edge cases and construction budget are explicit" do
    assert Enum.take(Havoc.Gen.byte_partitions(""), 1) == [[]]
    assert Enum.take(Havoc.Gen.byte_partitions("abc", max_chunks: 1), 1) == [["abc"]]
    assert_raise ArgumentError, fn -> Havoc.Gen.byte_partitions("abc", max_input_bytes: 2) end
  end

  defp capture(chunks) do
    Incremental.capture(
      chunks,
      %{buffer: "", work: 100},
      fn chunk, state ->
        buffer = state.buffer <> chunk
        work = state.work + byte_size(chunk)

        if String.ends_with?(buffer, "\n"),
          do: {:accepted, %{buffer: "", work: work}},
          else: {:incomplete, %{buffer: buffer, work: work}}
      end,
      fn state -> %{retained_bytes: byte_size(state.buffer), work: state.work} end,
      work_unit: :bytes_processed
    )
  end

  defp length_oracle, do: Oracle.bounded_length(unit: :bytes, max_length: 4)
  defp buffer_oracle, do: Oracle.incremental_buffer_budget(max_bytes: 4)

  defp work_oracle(maximum),
    do: Oracle.incremental_work_budget(unit: :bytes_processed, max_work: maximum)

  defp verdict(observation, input, oracle) do
    seed = %Core.Seed{id: "resource-contract", value: input, provenance: :generated}
    Havoc.validate(seed, fn _ -> observation end, oracles: [oracle], persist: false).verdict
  end
end
