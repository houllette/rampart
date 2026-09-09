defmodule Havoc.Result do
  @moduledoc "Versioned JSON persistence for Havoc-normalized findings."

  alias Havoc.{Corpus, TermCodec}

  @schema_version 1
  @locus_keys %{
    "action" => :action,
    "endpoint" => :endpoint,
    "function" => :function,
    "method" => :method,
    "module" => :module,
    "param" => :param,
    "property" => :property,
    "resource" => :resource,
    "url" => :url
  }
  @categories ~w(injection crash authz_bypass reflection sensitive_leak custom)
  @severities ~w(info low medium high critical)
  @confidences ~w(low medium high)

  @doc "Encodes a Havoc finding with an explicit schema version."
  @spec encode(Core.Finding.t()) :: {:ok, String.t()} | {:error, Jason.EncodeError.t()}
  def encode(%Core.Finding{} = finding), do: Jason.encode(to_map(finding))

  @doc "Encodes a Havoc finding or raises."
  @spec encode!(Core.Finding.t()) :: String.t()
  def encode!(%Core.Finding{} = finding), do: Jason.encode!(to_map(finding))

  @doc "Decodes a versioned Havoc finding."
  @spec decode(String.t()) :: {:ok, Core.Finding.t()} | {:error, term()}
  def decode(json) when is_binary(json) do
    with {:ok, map} <- Jason.decode(json), do: from_map(map)
  end

  defp to_map(finding) do
    unless finding.source == :havoc do
      raise ArgumentError, "Havoc.Result only encodes findings with source :havoc"
    end

    %{
      "schema_version" => @schema_version,
      "id" => finding.id,
      "source" => "havoc",
      "category" => encode_atom(finding.category),
      "locus" => encode_locus(finding.locus || %{}),
      "severity" => encode_atom(finding.severity),
      "confidence" => encode_atom(finding.confidence),
      "evidence" => finding.evidence,
      "raw" => TermCodec.encode(finding.raw),
      "seed" => encode_seed(finding.seed),
      "observed_at" => encode_datetime(finding.observed_at)
    }
  end

  defp from_map(%{"schema_version" => @schema_version} = map) do
    with "havoc" <- map["source"],
         {:ok, category} <- decode_enum(map["category"], @categories),
         {:ok, severity} <- decode_optional_enum(map["severity"], @severities),
         {:ok, confidence} <- decode_enum(map["confidence"], @confidences),
         {:ok, locus} <- decode_locus(map["locus"]),
         {:ok, raw} <- TermCodec.decode(map["raw"]),
         {:ok, seed} <- decode_seed(map["seed"]),
         {:ok, observed_at} <- decode_datetime(map["observed_at"]) do
      {:ok,
       %Core.Finding{
         id: map["id"],
         source: :havoc,
         category: category,
         locus: locus,
         severity: severity,
         confidence: confidence,
         evidence: map["evidence"],
         raw: raw,
         seed: seed,
         observed_at: observed_at
       }}
    else
      {:error, reason} -> {:error, {:invalid_finding, reason}}
      error -> {:error, {:invalid_finding, error}}
    end
  end

  defp from_map(%{"schema_version" => version}),
    do: {:error, {:unsupported_schema_version, version}}

  defp from_map(_map), do: {:error, :missing_schema_version}

  defp encode_locus(locus) do
    Map.new(locus, fn
      {key, value} when is_atom(key) -> {Atom.to_string(key), value}
      {key, value} when is_binary(key) -> {key, value}
    end)
  end

  defp decode_locus(locus) when is_map(locus) do
    unknown = Map.keys(locus) -- Map.keys(@locus_keys)

    if unknown == [] do
      {:ok, Map.new(locus, fn {key, value} -> {Map.fetch!(@locus_keys, key), value} end)}
    else
      {:error, {:unknown_locus_keys, unknown}}
    end
  end

  defp decode_locus(_locus), do: {:error, :invalid_locus}
  defp encode_seed(nil), do: nil
  defp encode_seed(%Core.Seed{} = seed), do: Corpus.seed_to_map(seed)
  defp decode_seed(nil), do: {:ok, nil}
  defp decode_seed(seed), do: Corpus.seed_from_map(seed)

  defp encode_datetime(nil), do: nil
  defp encode_datetime(datetime), do: DateTime.to_iso8601(datetime)
  defp decode_datetime(nil), do: {:ok, nil}

  defp decode_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, 0} -> {:ok, datetime}
      error -> {:error, {:invalid_datetime, error}}
    end
  end

  defp decode_datetime(_value), do: {:error, :invalid_datetime}
  defp encode_atom(nil), do: nil
  defp encode_atom(value), do: Atom.to_string(value)
  defp decode_optional_enum(nil, _allowed), do: {:ok, nil}
  defp decode_optional_enum(value, allowed), do: decode_enum(value, allowed)

  defp decode_enum(value, allowed) do
    if value in allowed, do: existing_atom(value), else: {:error, {:invalid_enum, value}}
  end

  defp existing_atom(value) when is_binary(value) do
    {:ok, String.to_existing_atom(value)}
  rescue
    ArgumentError -> {:error, {:unknown_atom, value}}
  end
end
