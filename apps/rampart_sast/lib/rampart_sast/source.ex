defmodule RampartSAST.Source do
  @moduledoc """
  One bounded Elixir or Erlang source snapshot parsed exactly once for a scan.

  The source hash and repository-relative path are stable evidence. The source
  bytes and AST remain native scanner data and are not placed directly in a
  transcript projection.
  """

  alias RampartSAST.{Diagnostic, Span, Suppression}

  @type language :: :elixir | :erlang | :erlang_terms
  @type origin :: %{
          required(:component_id) => String.t(),
          required(:kind) => :target | :dependency,
          required(:path) => Path.t(),
          optional(:package) => String.t() | nil,
          optional(:version) => String.t() | nil,
          optional(:checksum) => String.t() | nil
        }
  @type t :: %__MODULE__{
          path: Path.t(),
          language: language(),
          origin: origin(),
          hash: String.t(),
          bytes: non_neg_integer(),
          content: String.t(),
          ast: term(),
          comments: [map()],
          suppressions: [Suppression.t()]
        }

  @enforce_keys [
    :path,
    :language,
    :origin,
    :hash,
    :bytes,
    :content,
    :ast,
    :comments,
    :suppressions
  ]
  defstruct @enforce_keys

  @doc "Parses a bounded Elixir source snapshot and its structured comments."
  @spec parse(path :: Path.t(), content :: String.t(), max_bytes :: pos_integer()) ::
          {:ok, t(), [Diagnostic.t()]} | {:error, Diagnostic.t()}
  def parse(path, content, max_bytes)
      when is_binary(path) and is_binary(content) and is_integer(max_bytes) and max_bytes > 0 do
    cond do
      not Span.valid_file?(path) ->
        {:error, diagnostic(path, :invalid_path, "source path must be repository-relative")}

      byte_size(content) > max_bytes ->
        {:error,
         diagnostic(
           path,
           :file_size_limit,
           "source has #{byte_size(content)} bytes; limit is #{max_bytes}"
         )}

      true ->
        parse_content(path, content)
    end
  end

  @doc "Attaches validated workspace component provenance to a parsed source."
  @spec with_origin(t(), origin()) :: t()
  def with_origin(%__MODULE__{} = source, origin) when is_map(origin) do
    required = [:component_id, :kind, :path]

    valid? =
      Enum.all?(required, &Map.has_key?(origin, &1)) and
        nonempty_string?(origin.component_id) and origin.kind in [:target, :dependency] and
        Span.valid_file?(origin.path) and optional_string?(Map.get(origin, :package)) and
        optional_string?(Map.get(origin, :version)) and digest_or_nil?(Map.get(origin, :checksum))

    if valid?,
      do: %{source | origin: Map.take(origin, required ++ [:package, :version, :checksum])},
      else: raise(ArgumentError, "invalid SAST source origin: #{inspect(origin)}")
  end

  @doc "Returns the one-based source line, or nil when it does not exist."
  @spec line(source :: t(), line_number :: pos_integer()) :: String.t() | nil
  def line(%__MODULE__{content: content}, line_number)
      when is_integer(line_number) and line_number > 0 do
    content
    |> String.split("\n")
    |> Enum.at(line_number - 1)
  end

  @doc "Builds a replay seed containing this exact source snapshot."
  @spec seed(source :: t(), rule_id :: String.t() | nil) :: Core.Seed.t()
  def seed(%__MODULE__{} = source, rule_id \\ nil) do
    %Core.Seed{
      id: Core.Finding.dedupe_id(:sast, ["source_snapshot", source.path, source.hash]),
      value: %{path: source.path, content: source.content},
      classes: [:source_snapshot, :static_analysis],
      provenance: :generated,
      meta: %{source_hash: source.hash, rule_id: rule_id}
    }
  end

  defp parse_content(path, content) do
    case {Path.basename(path), Path.extname(path)} do
      {name, _extension} when name in ["rebar.config", "rebar.lock"] ->
        parse_erlang_term_file(path, content)

      {_name, extension} when extension in [".erl", ".hrl"] ->
        parse_erlang(path, content)

      {_name, _extension} ->
        parse_elixir(path, content)
    end
  rescue
    error in UnicodeConversionError ->
      {:error, diagnostic(path, :invalid_encoding, Exception.message(error))}
  end

  defp parse_elixir(path, content) do
    options = [file: path, columns: true, token_metadata: true, emit_warnings: false]

    case Code.string_to_quoted_with_comments(content, options) do
      {:ok, ast, comments} -> build(path, content, :elixir, ast, comments)
      {:error, error} -> {:error, diagnostic(path, :syntax_error, format_parse_error(error))}
    end
  end

  defp parse_erlang_term_file(path, content) do
    options = [:text, :return_comments]

    case :erl_scan.string(String.to_charlist(content), 1, options) do
      {:ok, tokens, _end_location} ->
        comments = erlang_comments(tokens)

        tokens
        |> Enum.reject(&(:erl_scan.category(&1) == :comment))
        |> split_erlang_tokens()
        |> parse_term_chunks([])
        |> case do
          {:ok, terms} -> build(path, content, :erlang_terms, terms, comments)
          {:error, error} -> {:error, erlang_diagnostic(path, error)}
        end

      {:error, error, _end_location} ->
        {:error, erlang_diagnostic(path, error)}
    end
  end

  defp parse_erlang(path, content) do
    options = [:text, :return_comments]

    case :erl_scan.string(String.to_charlist(content), 1, options) do
      {:ok, tokens, _end_location} -> parse_erlang_program(path, content, tokens)
      {:error, error, _end_location} -> {:error, erlang_diagnostic(path, error)}
    end
  end

  defp parse_erlang_program(path, content, tokens) do
    {:ok, device} = StringIO.open(content)

    try do
      {:ok, forms} = :epp_dodger.quick_parse(device)
      build_erlang(path, content, forms, erlang_comments(tokens))
    after
      StringIO.close(device)
    end
  end

  defp build_erlang(path, content, forms, comments) do
    case Enum.find(forms, &match?({:error, _error}, &1)) do
      {:error, error} -> {:error, erlang_diagnostic(path, error)}
      nil -> build(path, content, :erlang, forms, comments)
    end
  end

  defp split_erlang_tokens(tokens) do
    {forms, pending} =
      Enum.reduce(tokens, {[], []}, fn token, {forms, pending} ->
        if :erl_scan.category(token) == :dot do
          {[Enum.reverse([token | pending]) | forms], []}
        else
          {forms, [token | pending]}
        end
      end)

    case pending do
      [] -> Enum.reverse(forms)
      _tokens -> Enum.reverse([Enum.reverse(pending) | forms])
    end
  end

  defp parse_term_chunks([tokens | rest], terms) do
    case :erl_parse.parse_term(tokens) do
      {:ok, term} -> parse_term_chunks(rest, [term | terms])
      {:error, error} -> {:error, error}
    end
  end

  defp parse_term_chunks([], terms), do: {:ok, Enum.reverse(terms)}

  defp erlang_comments(tokens) do
    tokens
    |> Enum.filter(&(:erl_scan.category(&1) == :comment))
    |> Enum.map(fn token ->
      %{
        line: location_line(:erl_scan.location(token)),
        text: token |> :erl_scan.text() |> to_string()
      }
    end)
  end

  defp build(path, content, language, ast, comments) do
    {suppressions, diagnostics} = Suppression.parse(path, comments)

    {:ok,
     %__MODULE__{
       path: path,
       language: language,
       origin: default_origin(path),
       hash: digest(content),
       bytes: byte_size(content),
       content: content,
       ast: ast,
       comments: comments,
       suppressions: suppressions
     }, diagnostics}
  end

  defp diagnostic(path, code, message) do
    Diagnostic.new!(
      level: :error,
      phase: if(code == :file_size_limit, do: :limits, else: :parse),
      code: code,
      file: if(Span.valid_file?(path), do: path),
      message: message
    )
  end

  defp erlang_diagnostic(path, {location, module, description}) do
    message = module.format_error(description) |> IO.iodata_to_binary()
    diagnostic(path, :syntax_error, "#{format_erlang_location(location)}#{message}")
  end

  defp format_erlang_location(location) do
    case location do
      {line, column} -> "#{line}:#{column}: "
      line when is_integer(line) -> "#{line}: "
      _other -> ""
    end
  end

  defp location_line({line, _column}), do: line
  defp location_line(line) when is_integer(line), do: line

  defp format_parse_error({location, message, token}) do
    "#{format_location(location)}#{format_message(message, token)}"
  end

  defp format_location(location) when is_list(location) do
    line = Keyword.get(location, :line)
    column = Keyword.get(location, :column)

    case {line, column} do
      {nil, _column} -> ""
      {line, nil} -> "#{line}: "
      {line, column} -> "#{line}:#{column}: "
    end
  end

  defp format_message({prefix, suffix}, token), do: "#{prefix}#{token}#{suffix}"
  defp format_message(message, token) when is_binary(message), do: "#{message}#{token}"

  defp default_origin(path) do
    %{
      component_id: "target",
      kind: :target,
      path: path,
      package: nil,
      version: nil,
      checksum: nil
    }
  end

  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""
  defp optional_string?(nil), do: true
  defp optional_string?(value), do: nonempty_string?(value)
  defp digest_or_nil?(nil), do: true
  defp digest_or_nil?(value), do: is_binary(value) and byte_size(value) == 64

  defp digest(content) do
    :sha256
    |> :crypto.hash(content)
    |> Base.encode16(case: :lower)
  end
end
