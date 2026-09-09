defmodule RampartSAST.Suppression do
  @moduledoc """
  An explicit, rule-specific, reason-carrying source suppression.

  Only next-line suppressions are supported. They remain visible in scan results
  and never change whether validation proves that syntax is present.
  """

  alias RampartSAST.Diagnostic

  @type t :: %__MODULE__{
          rule_id: String.t(),
          comment_line: pos_integer(),
          target_line: pos_integer(),
          reason: String.t()
        }

  @enforce_keys [:rule_id, :comment_line, :target_line, :reason]
  defstruct @enforce_keys

  @valid_pattern ~r/^\s*[#%]\s*rampart:suppress-next-line\s+([a-z0-9][a-z0-9._-]*\.v[1-9][0-9]*)\s+--\s+(.+?)\s*$/
  @attempt_pattern ~r/rampart:suppress/

  @doc "Parses structured suppressions and malformed-suppression diagnostics from comments."
  @spec parse(file :: Path.t(), comments :: [map()]) :: {[t()], [Diagnostic.t()]}
  def parse(file, comments) when is_binary(file) and is_list(comments) do
    comments
    |> Enum.sort_by(&Map.get(&1, :line, 0))
    |> Enum.reduce({[], []}, &parse_comment(file, &1, &2))
    |> then(fn {suppressions, diagnostics} ->
      {Enum.reverse(suppressions), Enum.reverse(diagnostics)}
    end)
  end

  @doc "Returns whether a suppression applies to the given rule and source line."
  @spec applies?(suppression :: t(), rule_id :: String.t(), line :: pos_integer()) :: boolean()
  def applies?(%__MODULE__{} = suppression, rule_id, line) do
    suppression.rule_id == rule_id and suppression.target_line == line
  end

  @doc "Projects a suppression into plain evidence data."
  @spec to_map(suppression :: t()) :: map()
  def to_map(%__MODULE__{} = suppression) do
    %{
      rule_id: suppression.rule_id,
      comment_line: suppression.comment_line,
      target_line: suppression.target_line,
      reason: suppression.reason
    }
  end

  defp parse_comment(file, %{line: line, text: text}, {suppressions, diagnostics})
       when is_integer(line) and line > 0 and is_binary(text) do
    case Regex.run(@valid_pattern, text) do
      [_, rule_id, reason] ->
        suppression = %__MODULE__{
          rule_id: rule_id,
          comment_line: line,
          target_line: line + 1,
          reason: String.trim(reason)
        }

        {[suppression | suppressions], diagnostics}

      nil ->
        maybe_add_diagnostic(file, line, text, suppressions, diagnostics)
    end
  end

  defp parse_comment(_file, _comment, accumulator), do: accumulator

  defp maybe_add_diagnostic(file, line, text, suppressions, diagnostics) do
    if Regex.match?(@attempt_pattern, text) do
      diagnostic =
        Diagnostic.new!(
          level: :warning,
          phase: :suppression,
          code: :malformed_suppression,
          file: file,
          message: "line #{line}: expected `# rampart:suppress-next-line rule.id.v1 -- reason`"
        )

      {suppressions, [diagnostic | diagnostics]}
    else
      {suppressions, diagnostics}
    end
  end
end
