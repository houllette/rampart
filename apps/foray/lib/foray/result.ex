defmodule Foray.Result do
  @moduledoc "Versioned JSON persistence for Foray-normalized findings."

  @schema_version 1
  @locus_keys ~w(url method host param keyword input status length words lines content_type)
  @categories ~w(exposed_path param_injection vhost matched_response)
  @severities ~w(info low medium high critical)
  @confidences ~w(low medium high)
  @provenance ~w(wordlist generated counterexample promoted_finding)

  @doc "Encodes a Foray finding with an explicit schema version."
  @spec encode(Core.Finding.t()) :: {:ok, String.t()} | {:error, Jason.EncodeError.t()}
  def encode(%Core.Finding{} = finding), do: Jason.encode(to_map(finding))

  @doc "Encodes a finding or raises."
  @spec encode!(Core.Finding.t()) :: String.t()
  def encode!(%Core.Finding{} = finding), do: Jason.encode!(to_map(finding))

  @doc "Decodes a versioned Foray finding."
  @spec decode(String.t()) :: {:ok, Core.Finding.t()} | {:error, term()}
  def decode(json) when is_binary(json) do
    with {:ok, map} <- Jason.decode(json) do
      from_map(map)
    end
  end

  defp to_map(finding) do
    %{
      "schema_version" => @schema_version,
      "id" => finding.id,
      "source" => Atom.to_string(finding.source),
      "category" => Atom.to_string(finding.category),
      "locus" => stringify_keys(finding.locus),
      "severity" => encode_atom(finding.severity),
      "confidence" => encode_atom(finding.confidence),
      "evidence" => finding.evidence,
      "raw" => finding.raw,
      "seed" => encode_seed(finding.seed),
      "observed_at" => DateTime.to_iso8601(finding.observed_at)
    }
  end

  defp from_map(%{"schema_version" => @schema_version} = map) do
    with "foray" <- map["source"],
         {:ok, category} <- decode_enum(map["category"], @categories),
         {:ok, severity} <- decode_optional_enum(map["severity"], @severities),
         {:ok, confidence} <- decode_enum(map["confidence"], @confidences),
         {:ok, locus} <- decode_locus(map["locus"]),
         {:ok, seed} <- decode_seed(map["seed"]),
         {:ok, observed_at, 0} <- DateTime.from_iso8601(map["observed_at"]) do
      {:ok,
       struct(Core.Finding,
         id: map["id"],
         source: :foray,
         category: category,
         locus: locus,
         severity: severity,
         confidence: confidence,
         evidence: map["evidence"],
         raw: map["raw"],
         seed: seed,
         observed_at: observed_at
       )}
    else
      error -> {:error, {:invalid_finding, error}}
    end
  end

  defp from_map(%{"schema_version" => version}),
    do: {:error, {:unsupported_schema_version, version}}

  defp from_map(_map), do: {:error, :missing_schema_version}

  defp encode_seed(nil), do: nil

  defp encode_seed(%Core.Seed{} = seed) do
    %{
      "id" => seed.id,
      "value" => seed.value,
      "classes" => Enum.map(seed.classes, &Atom.to_string/1),
      "provenance" => encode_atom(seed.provenance),
      "origin" => encode_origin(seed.origin),
      "meta" => seed.meta
    }
  end

  defp decode_seed(nil), do: {:ok, nil}

  defp decode_seed(seed) when is_map(seed) do
    with {:ok, classes} <- decode_existing_atoms(seed["classes"]),
         {:ok, provenance} <- decode_optional_enum(seed["provenance"], @provenance),
         {:ok, origin} <- decode_origin(seed["origin"]) do
      {:ok,
       struct(Core.Seed,
         id: seed["id"],
         value: seed["value"],
         classes: classes,
         provenance: provenance,
         origin: origin,
         meta: seed["meta"] || %{}
       )}
    end
  end

  defp decode_seed(_seed), do: {:error, :invalid_seed}

  defp encode_origin(nil), do: nil
  defp encode_origin({source, id}), do: %{"source" => Atom.to_string(source), "finding_id" => id}

  defp decode_origin(nil), do: {:ok, nil}

  defp decode_origin(%{"source" => source, "finding_id" => finding_id}) do
    case existing_atom(source) do
      {:ok, source} -> {:ok, {source, finding_id}}
      error -> error
    end
  end

  defp decode_origin(_origin), do: {:error, :invalid_origin}

  defp decode_locus(locus) when is_map(locus) do
    unknown = Map.keys(locus) -- @locus_keys

    if unknown == [] do
      {:ok, Map.new(locus, fn {key, value} -> {String.to_existing_atom(key), value} end)}
    else
      {:error, {:unknown_locus_keys, unknown}}
    end
  end

  defp decode_locus(_locus), do: {:error, :invalid_locus}

  defp stringify_keys(map), do: Map.new(map, fn {key, value} -> {Atom.to_string(key), value} end)
  defp encode_atom(nil), do: nil
  defp encode_atom(value), do: Atom.to_string(value)

  defp decode_optional_enum(nil, _allowed), do: {:ok, nil}
  defp decode_optional_enum(value, allowed), do: decode_enum(value, allowed)

  defp decode_enum(value, allowed) do
    if value in allowed, do: existing_atom(value), else: {:error, {:invalid_enum, value}}
  end

  defp decode_existing_atoms(values) when is_list(values) do
    Enum.reduce_while(values, {:ok, []}, fn value, {:ok, atoms} ->
      case existing_atom(value) do
        {:ok, atom} -> {:cont, {:ok, [atom | atoms]}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, atoms} -> {:ok, Enum.reverse(atoms)}
      error -> error
    end
  end

  defp decode_existing_atoms(_values), do: {:error, :invalid_classes}

  defp existing_atom(value) when is_binary(value) do
    {:ok, String.to_existing_atom(value)}
  rescue
    ArgumentError -> {:error, {:unknown_atom, value}}
  end
end
