defmodule Havoc.GenTest do
  use ExUnit.Case, async: true

  alias Core.Seed

  test "built-in corpora are typed Core seeds with stable identities" do
    seeds = Havoc.Corpus.builtin(:sqli)

    assert [%Seed{} | _] = seeds
    assert Enum.all?(seeds, &(&1.classes == [:sqli]))
    assert Enum.all?(seeds, &(&1.provenance == :wordlist))
    assert Enum.all?(seeds, &(is_binary(&1.id) and is_binary(&1.value)))

    refute Enum.any?(
             seeds,
             &String.contains?(String.downcase(&1.value), ["drop table", "rm -rf"])
           )
  end

  test "injection generators compose requested classes as StreamData generators" do
    generator = Havoc.Gen.injection([:sqli, :xss], mutate: false)
    values = Enum.take(generator, 50)

    corpus_values =
      Enum.map(Havoc.Corpus.builtin(:sqli) ++ Havoc.Corpus.builtin(:xss), & &1.value)

    assert Enum.all?(values, &is_binary/1)
    assert Enum.all?(values, &(&1 in corpus_values))
  end

  test "structural generators are backed by null, malformed, boundary, and format inputs" do
    malformed_values =
      (Havoc.Corpus.builtin(:null_byte) ++ Havoc.Corpus.builtin(:malformed_utf8))
      |> Enum.map(& &1.value)

    format_values = Enum.map(Havoc.Corpus.builtin(:format_string), & &1.value)
    generated = Enum.take(Havoc.Gen.boundary(max_length: 128), 50)

    assert Enum.any?(malformed_values, &String.contains?(&1, <<0>>))
    assert Enum.any?(malformed_values, &(not String.valid?(&1)))
    assert Enum.all?(generated, &(is_binary(&1) and byte_size(&1) <= 128))
    assert Enum.all?(format_values, &String.contains?(&1, ["%", "~"]))
  end

  test "exports arbitrary payload enumerables as suite seeds" do
    seeds = Havoc.Corpus.export(["one", "two"], classes: [:xss], provenance: :generated)

    assert Enum.map(seeds, & &1.value) == ["one", "two"]
    assert Enum.all?(seeds, &(&1.classes == [:xss]))
    assert Enum.all?(seeds, &(&1.provenance == :generated))
    assert Enum.uniq_by(seeds, & &1.id) == seeds
  end
end
