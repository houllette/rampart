defmodule RampartSAST.SourceTest do
  use ExUnit.Case, async: true

  alias RampartSAST.{Source, Span}

  test "parses source once with comments, a stable hash, and an exact replay seed" do
    content = """
    defmodule Example do
      # ordinary comment
      def run(value), do: String.to_atom(value)
    end
    """

    assert {:ok, source, []} = Source.parse("lib/example.ex", content, 10_000)
    assert source.path == "lib/example.ex"
    assert source.language == :elixir
    assert source.bytes == byte_size(content)
    assert byte_size(source.hash) == 64
    assert source.comments != []
    assert Source.line(source, 3) =~ "String.to_atom"

    seed = Source.seed(source, "sast.unsafe-atom.v1")
    assert seed.value == %{path: "lib/example.ex", content: content}
    assert seed.meta.source_hash == source.hash
    assert seed.meta.rule_id == "sast.unsafe-atom.v1"
  end

  test "parses Erlang forms and produces line-independent AST anchors" do
    source =
      "-module(example).\n-define(DEFAULT, utf8).\nrun(Input) -> erlang:binary_to_atom(Input, ?DEFAULT).\n"

    moved = "\n\n" <> source

    assert {:ok, first, []} = Source.parse("src/example.erl", source, 10_000)
    assert {:ok, second, []} = Source.parse("src/example.erl", moved, 10_000)
    assert first.language == :erlang

    [first_call] = RampartSAST.AST.calls(first)
    [second_call] = RampartSAST.AST.calls(second)
    assert RampartSAST.Match.anchor(first_call.ast) == RampartSAST.Match.anchor(second_call.ast)
  end

  test "reports syntax errors instead of silently substituting an empty AST" do
    assert {:error, diagnostic} = Source.parse("lib/broken.ex", "defmodule Broken do", 1_000)
    assert diagnostic.level == :error
    assert diagnostic.phase == :parse
    assert diagnostic.code == :syntax_error
    assert diagnostic.file == "lib/broken.ex"

    assert {:error, erlang_diagnostic} =
             Source.parse("src/broken.erl", "-module(broken).\nrun( -> ok.\n", 1_000)

    assert erlang_diagnostic.code == :syntax_error
    assert erlang_diagnostic.file == "src/broken.erl"
  end

  test "rejects oversized source and paths outside the repository boundary" do
    assert {:error, oversized} = Source.parse("lib/large.ex", "12345", 4)
    assert oversized.code == :file_size_limit
    assert oversized.phase == :limits

    assert {:error, invalid_path} = Source.parse("../outside.ex", ":ok", 100)
    assert invalid_path.code == :invalid_path
    assert invalid_path.file == nil
  end

  test "source spans preserve columns and reject parent traversal" do
    span = Span.new!(file: "lib/example.ex", start_line: 2, start_column: 3)
    assert span.end_line == 2
    assert Span.to_map(span).start_column == 3

    assert_raise ArgumentError, ~r/invalid SAST source span/, fn ->
      Span.new!(file: "lib/../outside.ex", start_line: 1)
    end
  end
end
