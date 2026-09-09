defmodule Core.Validation.Wire do
  @moduledoc """
  Transcript-safe, JSON-shaped projections for validation tool adapters.

  Native Rampart values deliberately retain opaque `raw` terms and executable
  host context, so they are not safe transcript or RPC payloads. This module
  exposes a separate versioned projection that omits native raw values and, by
  default, the concrete seed value. The in-memory `Core.Validation.Result`
  remains the replay authority; a host may persist large or sensitive proof as
  content-addressed artifacts.

  The projection has no dependency on a particular harness. It is designed to
  fit structured tool-result contracts such as Lemieux's without making Core
  depend on Lemieux or restoring authority from a transcript.
  """

  alias Core.Validation.{Action, Evidence, Request, Result}

  @schema_version 1

  @doc "Returns a versioned action descriptor with a deterministic digest."
  @spec action(Action.t()) :: map()
  def action(%Action{} = action) do
    seal(%{
      "schema_version" => @schema_version,
      "id" => action.id,
      "tool" => Atom.to_string(action.tool),
      "name" => Atom.to_string(action.name),
      "description" => safe_text(action.description),
      "accepts" => Enum.map(action.accepts, &Atom.to_string/1),
      "side_effects" => Atom.to_string(action.side_effects),
      "meta" => json(action.meta)
    })
  end

  @doc "Returns the narrow JSON Schema accepted by a bound action adapter."
  @spec input_schema(Action.t()) :: map()
  def input_schema(%Action{} = action) do
    %{
      "type" => "object",
      "additionalProperties" => false,
      "required" => ["subject_type", "subject_id"],
      "properties" => %{
        "subject_type" => %{
          "type" => "string",
          "enum" => Enum.map(action.accepts, &Atom.to_string/1),
          "description" => "Kind of host-resolved Rampart subject"
        },
        "subject_id" => %{
          "type" => "string",
          "minLength" => 1,
          "description" => "Opaque identifier resolved under current host authority"
        }
      }
    }
  end

  @doc "Returns an inert subject reference; the subject body is never included."
  @spec subject_reference(Request.subject()) :: map()
  def subject_reference(%Core.Finding{id: id}), do: reference("finding", id)
  def subject_reference(%Core.Seed{id: id}), do: reference("seed", id)
  def subject_reference(%Core.Hypothesis{id: id}), do: reference("hypothesis", id)

  @doc "Returns a versioned structured result suitable for an audit transcript."
  @spec result(Result.t(), keyword()) :: map()
  def result(%Result{} = result, opts \\ []) when is_list(opts) do
    opts = Keyword.validate!(opts, include_seed_value: false)
    include_seed_value? = Keyword.fetch!(opts, :include_seed_value)

    unless is_boolean(include_seed_value?) do
      raise ArgumentError, ":include_seed_value must be a boolean"
    end

    seal(%{
      "schema_version" => @schema_version,
      "id" => result.id,
      "request_id" => result.request_id,
      "action" => action_reference(result.action),
      "tool" => Atom.to_string(result.tool),
      "verdict" => Atom.to_string(result.verdict),
      "evidence" => evidence(result.evidence),
      "findings" => Enum.map(result.findings, &finding/1),
      "finding_count" => length(result.findings),
      "seed" => seed(result.seed, include_seed_value?),
      "observed_at" => DateTime.to_iso8601(result.observed_at),
      "meta" => json(result.meta)
    })
  end

  @doc "Returns concise model-facing text without native raw evidence or payloads."
  @spec model_text(Result.t()) :: String.t()
  def model_text(%Result{} = result) do
    safe_text(
      "#{result.action.id}: #{result.verdict}. #{result.evidence.summary} " <>
        "Findings: #{length(result.findings)}. Replay seed: #{result.seed.id}."
    )
  end

  @doc "Encodes one JSON-shaped projection with the standard library encoder."
  @spec encode!(map()) :: String.t()
  def encode!(projection) when is_map(projection), do: JSON.encode!(projection)

  @doc "Verifies the digest on an action or result projection."
  @spec verify(map()) :: :ok | {:error, :missing_digest | :digest_mismatch}
  def verify(%{"sha256" => expected} = projection)
      when is_binary(expected) and byte_size(expected) == 64 do
    actual = projection |> Map.delete("sha256") |> digest()
    if :crypto.hash_equals(actual, expected), do: :ok, else: {:error, :digest_mismatch}
  end

  def verify(_projection), do: {:error, :missing_digest}

  @doc "Converts supported values to a string-keyed, JSON-safe shape."
  @spec json(term()) :: term()
  def json(value) when is_binary(value) do
    if String.valid?(value), do: value, else: binary_reference(value)
  end

  def json(value) when is_number(value) or is_boolean(value) or is_nil(value), do: value
  def json(value) when is_atom(value), do: Atom.to_string(value)
  def json(%DateTime{} = value), do: DateTime.to_iso8601(value)
  def json(%NaiveDateTime{} = value), do: NaiveDateTime.to_iso8601(value)

  def json(%_{} = value) do
    %{"$rampart" => "struct_omitted", "module" => value.__struct__ |> Atom.to_string()}
  end

  def json(value) when is_map(value) do
    Map.new(value, fn {key, item} -> {json_key(key), json(item)} end)
  end

  def json(value) when is_list(value), do: Enum.map(value, &json/1)
  def json(value) when is_tuple(value), do: value |> Tuple.to_list() |> Enum.map(&json/1)

  def json(value),
    do: %{"$rampart" => "value_omitted", "type" => unsupported_type(value)}

  defp reference(type, id) when is_binary(id) and byte_size(id) > 0 do
    %{"subject_type" => type, "subject_id" => id}
  end

  defp reference(_type, id) do
    raise ArgumentError, "validation subjects require a non-empty ID, got: #{inspect(id)}"
  end

  defp action_reference(%Action{} = action) do
    %{
      "id" => action.id,
      "tool" => Atom.to_string(action.tool),
      "name" => Atom.to_string(action.name)
    }
  end

  defp evidence(%Evidence{} = evidence) do
    %{
      "summary" => safe_text(evidence.summary),
      "facts" => json(evidence.facts),
      "artifacts" => Enum.map(evidence.artifacts, &json/1)
    }
  end

  defp finding(%Core.Finding{} = finding) do
    %{
      "id" => finding.id,
      "source" => atom_or_nil(finding.source),
      "category" => atom_or_nil(finding.category),
      "locus" => json(finding.locus),
      "severity" => atom_or_nil(finding.severity),
      "confidence" => atom_or_nil(finding.confidence),
      "evidence" => safe_text(finding.evidence),
      "seed_id" => seed_id(finding.seed),
      "observed_at" => datetime_or_nil(finding.observed_at)
    }
  end

  defp seed(%Core.Seed{} = seed, include_value?) do
    base = %{
      "id" => seed.id,
      "classes" => Enum.map(seed.classes, &Atom.to_string/1),
      "provenance" => atom_or_nil(seed.provenance),
      "origin" => json(seed.origin),
      "meta" => json(seed.meta),
      "value_included" => include_value?
    }

    if include_value?, do: Map.put(base, "value", json(seed.value)), else: base
  end

  defp seed_id(%Core.Seed{id: id}), do: id
  defp seed_id(_seed), do: nil

  defp datetime_or_nil(%DateTime{} = value), do: DateTime.to_iso8601(value)
  defp datetime_or_nil(_value), do: nil

  defp atom_or_nil(nil), do: nil
  defp atom_or_nil(value) when is_atom(value), do: Atom.to_string(value)

  defp json_key(value) when is_binary(value) do
    if String.valid?(value), do: value, else: "$binary_key_#{hash(value)}"
  end

  defp json_key(value) when is_atom(value), do: Atom.to_string(value)
  defp json_key(value) when is_integer(value), do: Integer.to_string(value)
  defp json_key(value), do: "$#{unsupported_type(value)}_key"

  defp safe_text(value) when is_binary(value) do
    if String.valid?(value), do: value, else: String.replace_invalid(value)
  end

  defp safe_text(nil), do: nil

  defp binary_reference(value) do
    %{
      "$rampart" => "binary_omitted",
      "size_bytes" => byte_size(value),
      "sha256" => hash(value)
    }
  end

  defp unsupported_type(value) do
    cond do
      is_function(value) -> "function"
      is_pid(value) -> "pid"
      is_port(value) -> "port"
      is_reference(value) -> "reference"
      is_bitstring(value) -> "bitstring"
      true -> "term"
    end
  end

  defp seal(projection), do: Map.put(projection, "sha256", digest(projection))

  defp digest(projection) do
    projection
    |> JSON.encode!()
    |> hash()
  end

  defp hash(value) do
    :sha256
    |> :crypto.hash(value)
    |> Base.encode16(case: :lower)
  end
end
