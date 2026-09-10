defmodule Havoc.Corpus do
  @moduledoc """
  Versioned, atomic storage for concrete security counterexamples.

  Corpus values are exact Elixir terms encoded without compression, protected by
  a digest, size-bounded, and decoded with `:erlang.binary_to_term/2`'s `:safe`
  option. Corpus files are local test artifacts and must not be accepted from an
  untrusted source without review.
  """

  alias Core.Seed
  alias Havoc.{Corpus.Error, TermCodec}

  @schema_version 1
  @max_corpus_bytes 16_777_216
  @injection_classes [
    :sqli,
    :xss,
    :path_traversal,
    :ssrf,
    :command_injection,
    :template_injection,
    :http_parameter_injection
  ]

  @builtins %{
    sqli: [
      "'",
      "\"",
      "' OR '1'='1' -- ",
      "') OR ('1'='1",
      "1 AND 1=2",
      "' HAVOC '"
    ],
    xss: [
      "<havoc-marker>",
      "\"><havoc-marker data-havoc=\"1\">",
      "'><havoc-marker>",
      "</textarea><havoc-marker>"
    ],
    path_traversal: [
      "../HAVOC",
      "../../HAVOC",
      "..%2f..%2fHAVOC",
      "%2e%2e/%2e%2e/HAVOC",
      "..\\..\\HAVOC"
    ],
    ssrf: [
      "https://havoc.invalid/ssrf/HAVOC",
      "//havoc.invalid/ssrf/HAVOC",
      "https://havoc.invalid:8443/HAVOC"
    ],
    command_injection: [
      "; printf HAVOC",
      "&& printf HAVOC",
      "| printf HAVOC",
      "$(printf HAVOC)",
      "`printf HAVOC`"
    ],
    template_injection: [
      "{{7*7}}HAVOC",
      "${7*7}HAVOC",
      "<%= 7 * 7 %>HAVOC",
      "\#{7*7}HAVOC"
    ],
    http_parameter_injection: [
      "HAVOC\"",
      "HAVOC\\",
      "HAVOC\", scope=\"admin",
      "HAVOC\r\nx-havoc: marker"
    ],
    null_byte: ["HAVOC\0", "\0HAVOC", "HAVOC\0.txt"],
    malformed_utf8: [<<255>>, <<192, 175>>, <<237, 160, 128>>, <<"HAVOC", 255>>],
    format_string: ["%s%s%s%sHAVOC", "%x%x%x%xHAVOC", "%nHAVOC", "~p~p~pHAVOC"]
  }

  @doc "Returns the supported injection classes."
  @spec injection_classes() :: [atom()]
  def injection_classes, do: @injection_classes

  @doc "Returns the inert, built-in seeds for a payload class."
  @spec builtin(class :: atom()) :: [Seed.t()]
  def builtin(class) when is_atom(class) do
    case Map.fetch(@builtins, class) do
      {:ok, values} -> export(values, classes: [class], provenance: :wordlist, source: :builtin)
      :error -> raise ArgumentError, "unknown built-in corpus class: #{inspect(class)}"
    end
  end

  @doc "Converts payload values into Core seeds without writing them."
  @spec export(values :: Enumerable.t(), opts :: keyword()) :: [Seed.t()]
  def export(values, opts \\ []) do
    schema = [
      classes: [type: {:list, :atom}, default: []],
      provenance: [type: :atom, default: :generated],
      origin: [type: :any, default: nil],
      meta: [type: :map, default: %{}],
      source: [type: :atom, default: :export]
    ]

    opts = NimbleOptions.validate!(opts, schema)

    Enum.map(values, fn value ->
      %Seed{
        id:
          Core.Finding.dedupe_id(:havoc, [
            "seed",
            opts[:source],
            TermCodec.fingerprint(value),
            TermCodec.fingerprint(opts[:classes])
          ]),
        value: value,
        classes: opts[:classes],
        provenance: opts[:provenance],
        origin: opts[:origin],
        meta: opts[:meta]
      }
    end)
  end

  @doc "Returns the configured corpus path."
  @spec path(opts :: keyword()) :: String.t()
  def path(opts \\ []) do
    Keyword.get(opts, :path) ||
      System.get_env("HAVOC_CORPUS_PATH") ||
      Application.get_env(:havoc, :corpus_path, "test/havoc/corpus.json")
  end

  @doc "Loads all seeds, optionally restricted to a property ID."
  @spec load(opts :: keyword()) :: [Seed.t()]
  def load(opts \\ []) do
    corpus_path = path(opts)

    corpus_path
    |> read_document!()
    |> decode_document!(corpus_path)
    |> filter_property(Keyword.get(opts, :property_id))
    |> Enum.sort_by(& &1.id)
  end

  @doc "Returns unique concrete values for a property in deterministic seed order."
  @spec replay_values(property_id :: String.t(), opts :: keyword()) :: [term()]
  def replay_values(property_id, opts \\ []) when is_binary(property_id) do
    opts
    |> Keyword.put(:property_id, property_id)
    |> load()
    |> Enum.reduce({MapSet.new(), []}, fn seed, {seen, values} ->
      fingerprint = TermCodec.fingerprint(seed.value)

      if MapSet.member?(seen, fingerprint) do
        {seen, values}
      else
        {MapSet.put(seen, fingerprint), [seed.value | values]}
      end
    end)
    |> elem(1)
    |> Enum.reverse()
  end

  @doc "Atomically inserts or replaces one seed by ID."
  @spec put(seed :: Seed.t(), opts :: keyword()) :: :ok
  def put(%Seed{} = seed, opts \\ []) do
    corpus_path = path(opts)
    seed = normalize_seed!(seed)

    locked(corpus_path, fn ->
      seeds = load(path: corpus_path)
      write_seeds!(corpus_path, upsert(seeds, seed))
    end)
  end

  @doc "Atomically imports Core seeds. `:property_id` can bind suite seeds to one property."
  @spec import(seeds :: Enumerable.t(), opts :: keyword()) :: {:ok, non_neg_integer()}
  def import(seeds, opts \\ []) do
    corpus_path = path(opts)
    property_id = Keyword.get(opts, :property_id)

    seeds =
      Enum.map(seeds, fn
        %Seed{} = seed -> seed |> bind_property(property_id) |> normalize_seed!()
        other -> raise ArgumentError, "expected a Core.Seed, got: #{inspect(other)}"
      end)

    locked(corpus_path, fn ->
      merged = Enum.reduce(seeds, load(path: corpus_path), &upsert(&2, &1))
      write_seeds!(corpus_path, merged)
    end)

    {:ok, length(seeds)}
  end

  @doc false
  @spec seed_to_map(Seed.t()) :: map()
  def seed_to_map(%Seed{} = seed) do
    %{
      "id" => seed.id,
      "value" => TermCodec.encode(seed.value),
      "classes" => Enum.map(seed.classes, &Atom.to_string/1),
      "provenance" => encode_atom(seed.provenance),
      "origin" => encode_origin(seed.origin),
      "meta" => TermCodec.encode(seed.meta)
    }
  end

  @doc false
  @spec seed_from_map(map()) :: {:ok, Seed.t()} | {:error, term()}
  def seed_from_map(map) when is_map(map) do
    with id when is_binary(id) and id != "" <- map["id"],
         {:ok, value} <- TermCodec.decode(map["value"]),
         {:ok, classes} <- decode_atoms(map["classes"]),
         {:ok, provenance} <- decode_optional_atom(map["provenance"]),
         {:ok, origin} <- decode_origin(map["origin"]),
         {:ok, meta} when is_map(meta) <- TermCodec.decode(map["meta"]) do
      {:ok,
       %Seed{
         id: id,
         value: value,
         classes: classes,
         provenance: provenance,
         origin: origin,
         meta: meta
       }}
    else
      false -> {:error, :invalid_seed_id}
      nil -> {:error, :invalid_seed_id}
      {:ok, _other} -> {:error, :invalid_seed_meta}
      {:error, _reason} = error -> error
      other -> {:error, {:invalid_seed, other}}
    end
  end

  def seed_from_map(_map), do: {:error, :invalid_seed}

  defp read_document!(corpus_path) do
    case File.stat(corpus_path) do
      {:ok, %{size: size}} when size > @max_corpus_bytes ->
        raise Error, reason: :corpus_too_large, path: corpus_path

      {:ok, _stat} ->
        case File.read(corpus_path) do
          {:ok, contents} -> decode_json!(contents, corpus_path)
          {:error, reason} -> raise Error, reason: reason, path: corpus_path
        end

      {:error, :enoent} ->
        %{"schema_version" => @schema_version, "seeds" => []}

      {:error, reason} ->
        raise Error, reason: reason, path: corpus_path
    end
  end

  defp decode_json!(contents, corpus_path) do
    case Jason.decode(contents) do
      {:ok, document} -> document
      {:error, reason} -> raise Error, reason: {:invalid_json, reason}, path: corpus_path
    end
  end

  defp decode_document!(%{"schema_version" => @schema_version, "seeds" => seeds}, corpus_path)
       when is_list(seeds) do
    Enum.map(seeds, fn encoded ->
      case seed_from_map(encoded) do
        {:ok, seed} -> seed
        {:error, reason} -> raise Error, reason: reason, path: corpus_path
      end
    end)
  end

  defp decode_document!(%{"schema_version" => version}, corpus_path) do
    raise Error, reason: {:unsupported_schema_version, version}, path: corpus_path
  end

  defp decode_document!(_document, corpus_path) do
    raise Error, reason: :invalid_document, path: corpus_path
  end

  defp write_seeds!(corpus_path, seeds) do
    document = %{
      "schema_version" => @schema_version,
      "seeds" => seeds |> Enum.sort_by(& &1.id) |> Enum.map(&seed_to_map/1)
    }

    parent = Path.dirname(corpus_path)
    File.mkdir_p!(parent)
    temporary = corpus_path <> ".tmp.#{System.unique_integer([:positive, :monotonic])}"

    try do
      File.write!(temporary, Jason.encode!(document), [:binary, :exclusive])
      File.chmod!(temporary, 0o600)
      File.rename!(temporary, corpus_path)
      :ok
    after
      File.rm(temporary)
    end
  end

  defp locked(corpus_path, operation) do
    lock_id = {{__MODULE__, Path.expand(corpus_path)}, self()}
    :global.trans(lock_id, operation)
  end

  defp normalize_seed!(%Seed{} = seed) do
    id = seed.id || Core.Finding.dedupe_id(:havoc, ["seed", TermCodec.fingerprint(seed.value)])

    unless is_binary(id) and id != "" do
      raise ArgumentError, "corpus seed id must be a non-empty string"
    end

    unless is_list(seed.classes) and Enum.all?(seed.classes, &is_atom/1) do
      raise ArgumentError, "corpus seed classes must be atoms"
    end

    unless is_map(seed.meta) do
      raise ArgumentError, "corpus seed metadata must be a map"
    end

    %{seed | id: id}
  end

  defp upsert(seeds, seed) do
    [seed | Enum.reject(seeds, &(&1.id == seed.id))]
  end

  defp bind_property(seed, nil), do: seed

  defp bind_property(seed, property_id) when is_binary(property_id) do
    %{seed | meta: Map.put(seed.meta, :property_id, property_id)}
  end

  defp filter_property(seeds, nil), do: seeds

  defp filter_property(seeds, property_id) do
    Enum.filter(seeds, &(Map.get(&1.meta, :property_id) == property_id))
  end

  defp encode_atom(nil), do: nil
  defp encode_atom(atom), do: Atom.to_string(atom)
  defp encode_origin(nil), do: nil

  defp encode_origin({source, finding_id}) do
    %{"source" => Atom.to_string(source), "finding_id" => finding_id}
  end

  defp decode_optional_atom(nil), do: {:ok, nil}
  defp decode_optional_atom(value), do: existing_atom(value)

  defp decode_atoms(values) when is_list(values) do
    Enum.reduce_while(values, {:ok, []}, fn value, {:ok, atoms} ->
      case existing_atom(value) do
        {:ok, atom} -> {:cont, {:ok, [atom | atoms]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, atoms} -> {:ok, Enum.reverse(atoms)}
      {:error, _reason} = error -> error
    end
  end

  defp decode_atoms(_values), do: {:error, :invalid_seed_classes}
  defp decode_origin(nil), do: {:ok, nil}

  defp decode_origin(%{"source" => source, "finding_id" => finding_id})
       when is_binary(finding_id) do
    with {:ok, source} <- existing_atom(source), do: {:ok, {source, finding_id}}
  end

  defp decode_origin(_origin), do: {:error, :invalid_seed_origin}

  defp existing_atom(value) when is_binary(value) do
    {:ok, String.to_existing_atom(value)}
  rescue
    ArgumentError -> {:error, {:unknown_atom, value}}
  end

  defp existing_atom(value), do: {:error, {:invalid_atom, value}}
end
