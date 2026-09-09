defmodule RampartSAST.Component do
  @moduledoc "A checksummed target or dependency source component in a cross-package workspace."

  alias RampartSAST.Span

  @type source_entry :: {Path.t(), String.t()}
  @type kind :: :target | :dependency
  @type t :: %__MODULE__{
          id: String.t(),
          kind: kind(),
          package: String.t() | nil,
          version: String.t() | nil,
          checksum: String.t(),
          sources: [source_entry()]
        }

  @enforce_keys [:id, :kind, :checksum, :sources]
  defstruct [:id, :kind, :package, :version, :checksum, :sources]

  @doc "Builds a component and verifies an optional expected source checksum."
  @spec new!(keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes, [:id, :kind, :package, :version, :checksum, :sources])

    id = Keyword.fetch!(attributes, :id)
    kind = Keyword.fetch!(attributes, :kind)
    sources = attributes |> Keyword.fetch!(:sources) |> validate_sources!()
    package = attributes[:package]
    version = attributes[:version]
    checksum = checksum(sources)

    validate_id!(id)
    validate_kind!(kind)
    validate_optional_string!(package)
    validate_optional_string!(version)
    validate_dependency_package!(kind, package)
    validate_checksum!(attributes[:checksum], checksum)

    %__MODULE__{
      id: id,
      kind: kind,
      package: package,
      version: version,
      checksum: checksum,
      sources: sources
    }
  end

  @doc "Returns the deterministic SHA-256 checksum of sorted component source paths and bytes."
  @spec checksum([source_entry()]) :: String.t()
  def checksum(sources) when is_list(sources) do
    sources
    |> Enum.sort_by(&elem(&1, 0))
    |> :erlang.term_to_binary([:deterministic])
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  @doc "Projects component provenance without source bytes."
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = component) do
    %{
      id: component.id,
      kind: component.kind,
      package: component.package,
      version: component.version,
      checksum: component.checksum,
      source_count: length(component.sources)
    }
  end

  defp validate_sources!(sources) when is_list(sources) and sources != [] do
    valid? =
      Enum.all?(sources, fn
        {path, content} -> Span.valid_file?(path) and is_binary(content)
        _other -> false
      end)

    paths = Enum.map(sources, &elem(&1, 0))

    if valid? and length(Enum.uniq(paths)) == length(paths) do
      Enum.sort_by(sources, &elem(&1, 0))
    else
      raise ArgumentError, "SAST component sources must have unique relative paths and bytes"
    end
  end

  defp validate_sources!(_sources) do
    raise ArgumentError, "SAST components require a non-empty source list"
  end

  defp validate_id!(id) do
    unless nonempty_string?(id) and Regex.match?(~r/^[A-Za-z0-9][A-Za-z0-9._-]*$/, id),
      do: raise(ArgumentError, "invalid SAST workspace component ID")
  end

  defp validate_kind!(kind) when kind in [:target, :dependency], do: :ok
  defp validate_kind!(_kind), do: raise(ArgumentError, "invalid SAST workspace component kind")

  defp validate_optional_string!(nil), do: :ok

  defp validate_optional_string!(value) when is_binary(value) do
    unless String.trim(value) != "",
      do: raise(ArgumentError, "SAST component package and version must not be blank")
  end

  defp validate_optional_string!(_value) do
    raise ArgumentError, "SAST component package and version must be strings"
  end

  defp validate_dependency_package!(:target, _package), do: :ok

  defp validate_dependency_package!(:dependency, package) do
    unless nonempty_string?(package),
      do: raise(ArgumentError, "SAST dependency components require a package")
  end

  defp validate_checksum!(nil, _actual), do: :ok
  defp validate_checksum!(checksum, checksum), do: :ok

  defp validate_checksum!(_expected, _actual) do
    raise ArgumentError, "SAST component checksum does not match its sources"
  end

  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
end
