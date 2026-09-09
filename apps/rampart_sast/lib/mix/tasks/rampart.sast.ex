defmodule Mix.Tasks.Rampart.Sast do
  @moduledoc "Builds RampartSAST reconnaissance facts and runs its sink-signal starter pack."

  use Mix.Task

  @shortdoc "Builds a deterministic static reconnaissance inventory"

  @switches [exit: :boolean, fail_on_signals: :boolean, root: :string]

  @impl Mix.Task
  @spec run(arguments :: [String.t()]) :: :ok
  def run(arguments) do
    Mix.Task.run("app.start")
    {options, remaining} = OptionParser.parse!(arguments, strict: @switches)

    if remaining != [],
      do: Mix.raise("unexpected rampart.sast arguments: #{Enum.join(remaining, " ")}")

    result =
      options
      |> Keyword.get(:root, File.cwd!())
      |> RampartSAST.scan(RampartSAST.default_rules())

    print_result(result)
    enforce_exit(result, options)
  end

  defp print_result(result) do
    Enum.each(result.observations, fn signal ->
      location = "#{signal.span.file}:#{signal.span.start_line}"
      Mix.shell().info("#{location} #{signal.rule.id} #{signal.message}")
    end)

    Enum.each(result.diagnostics, fn diagnostic ->
      location = if diagnostic.file, do: "#{diagnostic.file} ", else: ""

      Mix.shell().error(
        "#{location}#{diagnostic.phase}.#{diagnostic.code}: #{diagnostic.message}"
      )
    end)

    Mix.shell().info(
      "RampartSAST: #{length(result.observations)} rule signals, " <>
        "#{length(result.inventory.facts)} inventory facts, " <>
        "#{length(result.suppressed)} suppressed, status #{result.status}"
    )
  end

  defp enforce_exit(%{status: :incomplete}, _options),
    do: Mix.raise("RampartSAST scan was incomplete")

  defp enforce_exit(%{observations: [_first | _rest]}, options) do
    if options[:fail_on_signals], do: Mix.raise("RampartSAST rule signals require review")
  end

  defp enforce_exit(_result, _options), do: :ok
end
