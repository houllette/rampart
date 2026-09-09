defmodule MuexSecurity do
  @moduledoc "Focused, reviewable security-control mutation operators for Muex."

  alias MuexSecurity.Mutator

  @doc "Returns the stable CLI-name registry for this operator pack."
  @spec mutators() :: %{String.t() => module()}
  def mutators do
    %{
      "sanitizer_bypass" => Mutator.SanitizerBypass,
      "secure_compare" => Mutator.SecureCompare,
      "security_decision" => Mutator.SecurityDecision,
      "security_header" => Mutator.SecurityHeader,
      "transport_security" => Mutator.TransportSecurity
    }
  end

  @doc "Builds a Muex config from normal CLI arguments, selecting only security operators."
  @spec configure([String.t()]) :: {:ok, Muex.Config.t()} | {:error, String.t()}
  def configure(args \\ []) when is_list(args) do
    with {:ok, names, muex_args} <- extract_mutator_names(args),
         {:ok, modules} <- resolve_mutators(names),
         {:ok, config} <- Muex.Config.from_args(muex_args) do
      {:ok, %{config | mutators: modules}}
    end
  end

  @doc "Runs Muex with this pack and returns Muex's unmodified result."
  @spec run([String.t()]) :: {:ok, map()} | {:error, String.t()}
  def run(args \\ []) do
    with {:ok, config} <- configure(args), do: Muex.run(config)
  end

  defp extract_mutator_names(args), do: extract_mutator_names(args, nil, [])

  defp extract_mutator_names([], selection, kept) do
    names = selection || Map.keys(mutators())
    {:ok, names, Enum.reverse(kept)}
  end

  defp extract_mutator_names(["--mutators", value | rest], nil, kept) do
    extract_mutator_names(rest, split_names(value), kept)
  end

  defp extract_mutator_names(["--mutators=" <> value | rest], nil, kept) do
    extract_mutator_names(rest, split_names(value), kept)
  end

  defp extract_mutator_names(["--mutators" | _rest], _selection, _kept) do
    {:error, "--mutators may be specified only once"}
  end

  defp extract_mutator_names(["--mutators=" <> _value | _rest], _selection, _kept) do
    {:error, "--mutators may be specified only once"}
  end

  defp extract_mutator_names([arg | rest], selection, kept) do
    extract_mutator_names(rest, selection, [arg | kept])
  end

  defp split_names(value) do
    value
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  defp resolve_mutators([]), do: {:error, "at least one security mutator is required"}

  defp resolve_mutators(names) do
    registry = mutators()

    Enum.reduce_while(names, {:ok, []}, fn name, {:ok, modules} ->
      case Map.fetch(registry, name) do
        {:ok, module} -> {:cont, {:ok, [module | modules]}}
        :error -> {:halt, {:error, "unknown security mutator: #{name}"}}
      end
    end)
    |> then(fn
      {:ok, modules} -> {:ok, Enum.reverse(modules)}
      error -> error
    end)
  end
end
