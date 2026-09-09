defmodule RampartSAST.ProjectRuleFixture do
  @moduledoc false
  @behaviour RampartSAST.Rule

  alias RampartSAST.{Match, Source}
  alias RampartSAST.Rule.Descriptor

  @impl true
  def descriptor do
    Descriptor.new!(
      id: "test.project-rule.v1",
      schema_version: 1,
      title: "Project fixture",
      description: "Emits one project-scoped fixture match.",
      category: :test_static,
      severity: :low,
      confidence: :high,
      scope: :project
    )
  end

  @impl true
  def run_project([%Source{} = source | _rest], _context, _options) do
    [Match.from_ast(source, source.ast, message: "project fixture matched")]
  end

  def run_project([], _context, _options), do: []
end

defmodule RampartSAST.DuplicateRuleFixture do
  @moduledoc false
  @behaviour RampartSAST.Rule

  alias RampartSAST.{Match, Source}
  alias RampartSAST.Rule.Descriptor

  @impl true
  def descriptor do
    Descriptor.new!(
      id: "test.duplicate-rule.v1",
      schema_version: 1,
      title: "Duplicate fixture",
      description: "Emits the same match twice.",
      category: :test_static,
      severity: :low,
      confidence: :low,
      scope: :source
    )
  end

  @impl true
  def run_source(%Source{} = source, _context, _options) do
    match = Match.from_ast(source, source.ast, message: "duplicate fixture matched")
    [match, match]
  end
end

defmodule RampartSAST.OptionRuleFixture do
  @moduledoc false
  @behaviour RampartSAST.Rule

  alias RampartSAST.{Match, Source}
  alias RampartSAST.Rule.Descriptor

  @impl true
  def descriptor do
    Descriptor.new!(
      id: "test.option-rule.v1",
      schema_version: 1,
      title: "Option fixture",
      description: "Can fail under host-selected test options.",
      category: :test_static,
      severity: :low,
      confidence: :high,
      scope: :source
    )
  end

  @impl true
  def run_source(%Source{} = source, _context, options) do
    if options[:fail] do
      raise "option fixture failed"
    else
      [Match.from_ast(source, source.ast, message: "option fixture matched")]
    end
  end
end

defmodule RampartSAST.BrokenRuleFixture do
  @moduledoc false
  @behaviour RampartSAST.Rule

  alias RampartSAST.Rule.Descriptor

  @impl true
  def descriptor do
    Descriptor.new!(
      id: "test.broken-rule.v1",
      schema_version: 1,
      title: "Broken fixture",
      description: "Raises during test execution.",
      category: :test_static,
      severity: :low,
      confidence: :low,
      scope: :source
    )
  end

  @impl true
  def run_source(_source, _context, _options), do: raise("fixture rule failed")
end

defmodule RampartSAST.SlowRuleFixture do
  @moduledoc false
  @behaviour RampartSAST.Rule

  alias RampartSAST.Rule.Descriptor

  @impl true
  def descriptor do
    Descriptor.new!(
      id: "test.slow-rule.v1",
      schema_version: 1,
      title: "Slow fixture",
      description: "Exceeds a configured rule deadline.",
      category: :test_static,
      severity: :low,
      confidence: :low,
      scope: :source
    )
  end

  @impl true
  def run_source(_source, _context, _options) do
    Process.sleep(:infinity)
  end
end

defmodule RampartSAST.InvalidContextFixture do
  @moduledoc false
  @behaviour RampartSAST.ContextProvider

  @impl true
  def id, do: "test.invalid-context.v1"

  @impl true
  def build(_sources, _options), do: {:ok, %{project: %{}, sources: %{"missing.ex" => %{}}}}
end

defmodule RampartSAST.SlowBehaviorFixture do
  @moduledoc false
  @behaviour RampartSAST.Behavior

  @impl true
  def id, do: "test.slow-behavior.v1"

  @impl true
  def classify(_fact, _options), do: Process.sleep(:infinity)
end

defmodule RampartSAST.SlowContextFixture do
  @moduledoc false
  @behaviour RampartSAST.ContextProvider

  @impl true
  def id, do: "test.slow-context.v1"

  @impl true
  def build(_sources, _options), do: Process.sleep(:infinity)
end
