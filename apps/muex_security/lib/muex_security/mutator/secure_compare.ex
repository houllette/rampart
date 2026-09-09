defmodule MuexSecurity.Mutator.SecureCompare do
  @moduledoc "Downgrades recognized constant-time equality calls to ordinary equality."

  @behaviour Muex.Mutator

  alias MuexSecurity.Mutation

  @impl true
  def name, do: "SecureCompare"

  @impl true
  def description, do: "Replaces constant-time secret comparison with =="

  @impl true
  def supported_languages, do: [Muex.Language.Elixir]

  @impl true
  def mutate({{:., _dot_metadata, [receiver, function]}, metadata, [left, right]}, context) do
    if secure_compare?(receiver, function) do
      [downgrade(left, right, metadata, context, "#{module_name(receiver)}.#{function}/2")]
    else
      []
    end
  end

  def mutate(_ast, _context), do: []

  defp secure_compare?({:__aliases__, _metadata, [:Plug, :Crypto]}, :secure_compare), do: true
  defp secure_compare?(:crypto, :hash_equals), do: true
  defp secure_compare?(_receiver, _function), do: false

  defp downgrade(left, right, metadata, context, call) do
    Mutation.build(
      __MODULE__,
      {:==, metadata, [left, right]},
      "downgrade #{call}",
      context,
      metadata
    )
  end

  defp module_name({:__aliases__, _metadata, names}) do
    Enum.map_join(names, ".", &Atom.to_string/1)
  end

  defp module_name(module), do: inspect(module)
end
