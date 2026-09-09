defmodule RampartIAST.StaticProvenance do
  @moduledoc """
  Reproducibility metadata for one reviewed static-analysis candidate.

  The analyzer, exact version, rule identity, and source revision are mandatory
  so a later runtime result can name the static knowledge that produced its
  hypothesis without treating that knowledge as proof.
  """

  @type t :: %__MODULE__{
          analyzer: String.t(),
          analyzer_version: String.t(),
          rule_id: String.t(),
          source_revision: String.t(),
          plugins: %{optional(String.t()) => String.t()}
        }

  @enforce_keys [:analyzer, :analyzer_version, :rule_id, :source_revision]
  defstruct @enforce_keys ++ [plugins: %{}]

  @doc "Builds and validates static-analysis provenance."
  @spec new!(attributes :: keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [
        :analyzer,
        :analyzer_version,
        :rule_id,
        :source_revision,
        plugins: %{}
      ])

    attributes
    |> then(&struct!(__MODULE__, &1))
    |> validate!()
  end

  @doc "Validates static-analysis provenance and returns it."
  @spec validate!(provenance :: t()) :: t()
  def validate!(%__MODULE__{} = provenance) do
    valid? =
      Enum.all?(
        [
          provenance.analyzer,
          provenance.analyzer_version,
          provenance.rule_id,
          provenance.source_revision
        ],
        &nonempty_string?/1
      ) and valid_plugins?(provenance.plugins)

    if valid?,
      do: provenance,
      else: raise(ArgumentError, "invalid IAST static provenance: #{inspect(provenance)}")
  end

  @doc "Projects provenance into plain, transcript-safe data."
  @spec to_map(provenance :: t()) :: map()
  def to_map(%__MODULE__{} = provenance) do
    %{
      analyzer: provenance.analyzer,
      analyzer_version: provenance.analyzer_version,
      rule_id: provenance.rule_id,
      source_revision: provenance.source_revision,
      plugins: provenance.plugins
    }
  end

  defp valid_plugins?(plugins) when is_map(plugins) do
    Enum.all?(plugins, fn {name, version} ->
      nonempty_string?(name) and nonempty_string?(version)
    end)
  end

  defp valid_plugins?(_plugins), do: false
  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
end
