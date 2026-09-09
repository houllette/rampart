defmodule Mix.Tasks.Muex.Security do
  use Mix.Task

  @shortdoc "Runs Muex with Rampart's focused security operator pack"

  @moduledoc """
  Runs Muex with only MuexSecurity operators. Every ordinary Muex option is
  forwarded; `--mutators` selects a comma-separated subset of this pack.

      mix muex.security --files lib/my_app --test-paths test/security
      mix muex.security --mutators security_decision,secure_compare
  """

  @impl Mix.Task
  def run(args) do
    Mix.Task.run("compile")

    with {:ok, config} <- MuexSecurity.configure(args),
         {:ok, result} <- Muex.run(config) do
      enforce_threshold!(result, config.fail_at)
    else
      {:error, reason} -> Mix.raise(reason)
    end
  end

  defp enforce_threshold!(%{score_low: score_low, score_high: score_high}, threshold)
       when score_low < threshold do
    score = if score_low == score_high, do: "#{score_low}%", else: "#{score_low}%..#{score_high}%"
    Mix.raise("Mutation score #{score} is below threshold #{threshold}%")
  end

  defp enforce_threshold!(%{results: []}, _threshold) do
    Mix.shell().info("No security mutations to test; nothing to score.")
    :ok
  end

  defp enforce_threshold!(_result, _threshold), do: :ok
end
