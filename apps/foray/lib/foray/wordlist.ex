defmodule Foray.Wordlist do
  @moduledoc "A file, Core seed corpus, or explicit ffuf input-command source."

  @type source ::
          {:file, Path.t()}
          | {:seeds, [Core.Seed.t()]}
          | {:command, String.t(), pos_integer(), String.t() | nil}

  @type t :: %__MODULE__{
          ref: String.t(),
          keyword: String.t(),
          source: source(),
          classes: [atom()]
        }

  @enforce_keys [:ref, :keyword, :source]
  defstruct [:ref, :keyword, :source, classes: []]

  @doc false
  @spec index(wordlists :: [t()]) :: [{String.t(), map()}]
  def index(wordlists) do
    for %__MODULE__{keyword: keyword, source: {:seeds, seeds}} <- wordlists do
      values =
        Enum.reduce(seeds, %{}, fn seed, acc ->
          Map.put_new(acc, seed_value(seed), seed)
        end)

      {keyword, Map.delete(values, nil)}
    end
  end

  @doc false
  @spec indexed_seed(index :: [{String.t(), map()}], inputs :: map()) :: Core.Seed.t() | nil
  def indexed_seed(index, inputs) do
    Enum.find_value(index, fn {keyword, values} -> Map.get(values, inputs[keyword]) end)
  end

  @doc false
  @spec seed_for([t()], map()) :: Core.Seed.t() | nil
  def seed_for(wordlists, inputs) when is_list(wordlists) and is_map(inputs) do
    Enum.find_value(wordlists, fn
      %__MODULE__{keyword: keyword, source: {:seeds, seeds}} ->
        case Map.fetch(inputs, keyword) do
          {:ok, value} -> Enum.find(seeds, &(seed_value(&1) == value))
          :error -> nil
        end

      %__MODULE__{} ->
        nil
    end)
  end

  defp seed_value(%Core.Seed{value: value}) when is_binary(value), do: value
  defp seed_value(_seed), do: nil
end
