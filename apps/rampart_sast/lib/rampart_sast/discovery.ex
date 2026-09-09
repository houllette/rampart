defmodule RampartSAST.Discovery do
  @moduledoc false

  alias RampartSAST.{Diagnostic, Limits, Span}
  alias RampartSAST.Discovery.FileSystem

  @default_include [
    "lib/**/*.{ex,exs}",
    "src/**/*.{erl,hrl}",
    "include/**/*.hrl",
    "test/**/*.{ex,exs,erl,hrl}",
    "config/**/*.exs",
    "mix.exs",
    "mix.lock",
    "rebar.config",
    "rebar.lock",
    "apps/*/lib/**/*.{ex,exs}",
    "apps/*/src/**/*.{erl,hrl}",
    "apps/*/include/**/*.hrl",
    "apps/*/test/**/*.{ex,exs,erl,hrl}",
    "apps/*/mix.exs",
    "apps/*/rebar.config",
    "apps/*/rebar.lock"
  ]

  @spec read(root :: Path.t(), options :: keyword(), limits :: Limits.t()) ::
          {entries :: [{Path.t(), String.t()}], [Diagnostic.t()], map()}
  def read(root, options, %Limits{} = limits) when is_binary(root) and is_list(options) do
    root = Path.expand(root)

    unless File.dir?(root), do: raise(ArgumentError, "SAST root is not a directory: #{root}")

    options = Keyword.validate!(options, include: @default_include, exclude: [])
    {included, include_symlinks} = paths(root, options[:include])
    {excluded, exclude_symlinks} = paths(root, options[:exclude])
    excluded = MapSet.new(excluded)

    candidates =
      included
      |> Enum.reject(&MapSet.member?(excluded, &1))
      |> Enum.uniq()
      |> Enum.sort()

    {files, diagnostics} = classify_files(root, candidates)

    symlink_diagnostics =
      include_symlinks
      |> Kernel.++(exclude_symlinks)
      |> Enum.uniq()
      |> Enum.map(&symlink_diagnostic(Path.relative_to(&1, root)))

    diagnostics = symlink_diagnostics ++ diagnostics
    metrics = %{discovered_file_count: length(files), discovered_bytes: total_bytes(files)}

    cond do
      length(files) > limits.max_files ->
        diagnostic =
          Diagnostic.new!(
            level: :error,
            phase: :limits,
            code: :file_count_limit,
            message: "discovered #{length(files)} files; limit is #{limits.max_files}"
          )

        {[], sort_diagnostics([diagnostic | diagnostics]), metrics}

      metrics.discovered_bytes > limits.max_total_bytes ->
        diagnostic =
          Diagnostic.new!(
            level: :error,
            phase: :limits,
            code: :total_size_limit,
            message:
              "discovered #{metrics.discovered_bytes} source bytes; limit is #{limits.max_total_bytes}"
          )

        {[], sort_diagnostics([diagnostic | diagnostics]), metrics}

      true ->
        {entries, read_diagnostics} = read_files(files, limits)
        {entries, sort_diagnostics(diagnostics ++ read_diagnostics), metrics}
    end
  end

  defp paths(_root, []), do: {[], []}

  defp paths(root, patterns) when is_list(patterns) do
    Enum.reduce(patterns, {[], []}, fn pattern, {all_matches, all_symlinks} ->
      validate_pattern!(pattern)
      {matches, symlinks} = FileSystem.wildcard(root, pattern)
      matches = reject_implicit_dot_matches(matches, pattern)

      absolute_matches = Enum.map(matches, &Path.expand(&1, root))
      {absolute_matches ++ all_matches, symlinks ++ all_symlinks}
    end)
  end

  defp validate_pattern!(pattern) when is_binary(pattern) do
    valid? =
      String.trim(pattern) != "" and Path.type(pattern) == :relative and
        ".." not in Path.split(pattern)

    unless valid?,
      do: raise(ArgumentError, "SAST globs must be non-empty and remain within the selected root")
  end

  defp validate_pattern!(_pattern) do
    raise ArgumentError, "SAST include/exclude patterns must be strings"
  end

  defp reject_implicit_dot_matches(matches, pattern) do
    if Enum.any?(Path.split(pattern), &String.starts_with?(&1, ".")) do
      matches
    else
      Enum.reject(matches, &hidden_path?/1)
    end
  end

  defp hidden_path?(path) do
    Enum.any?(Path.split(path), &hidden_component?/1)
  end

  defp hidden_component?(component) do
    String.starts_with?(component, ".") and component not in [".", ".."]
  end

  defp classify_files(root, candidates) do
    candidates
    |> Enum.reduce({[], []}, &classify_file(root, &1, &2))
    |> then(fn {files, diagnostics} -> {Enum.sort(files), diagnostics} end)
  end

  defp classify_file(root, path, {files, diagnostics}) do
    relative = Path.relative_to(path, root)

    if symlink_component?(root, relative) do
      {files, [symlink_diagnostic(relative) | diagnostics]}
    else
      classify_non_symlink(path, relative, files, diagnostics)
    end
  end

  defp classify_non_symlink(path, relative, files, diagnostics) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} ->
        add_regular_file(path, relative, size, files, diagnostics)

      {:ok, _stat} ->
        {files, diagnostics}

      {:error, reason} ->
        {files, [file_diagnostic(relative, :stat_failed, reason) | diagnostics]}
    end
  end

  defp symlink_component?(root, relative) do
    relative
    |> Path.split()
    |> Enum.reduce_while(root, fn component, parent ->
      path = Path.join(parent, component)

      case File.lstat(path) do
        {:ok, %File.Stat{type: :symlink}} -> {:halt, true}
        _other -> {:cont, path}
      end
    end)
    |> Kernel.==(true)
  end

  defp add_regular_file(path, relative, size, files, diagnostics) do
    if Span.valid_file?(relative) do
      {[{path, relative, size} | files], diagnostics}
    else
      {files, [scope_diagnostic(relative) | diagnostics]}
    end
  end

  defp read_files(files, limits) do
    files
    |> Enum.reduce({[], []}, &read_file(&1, limits, &2))
    |> then(fn {entries, diagnostics} ->
      entries = Enum.sort_by(entries, &elem(&1, 0))
      {entries, diagnostics}
    end)
  end

  defp read_file({_absolute, relative, size}, limits, {entries, diagnostics})
       when size > limits.max_file_bytes do
    diagnostic =
      Diagnostic.new!(
        level: :error,
        phase: :limits,
        code: :file_size_limit,
        file: relative,
        message: "source has #{size} bytes; limit is #{limits.max_file_bytes}"
      )

    {entries, [diagnostic | diagnostics]}
  end

  defp read_file({absolute, relative, _size}, _limits, {entries, diagnostics}) do
    case File.read(absolute) do
      {:ok, content} ->
        {[{relative, content} | entries], diagnostics}

      {:error, reason} ->
        {entries, [file_diagnostic(relative, :read_failed, reason) | diagnostics]}
    end
  end

  defp total_bytes(files),
    do: Enum.reduce(files, 0, fn {_path, _relative, size}, sum -> sum + size end)

  defp symlink_diagnostic(relative) do
    Diagnostic.new!(
      level: :warning,
      phase: :discovery,
      code: :symlink_ignored,
      file: relative,
      message: "symbolic-link source was ignored to preserve the selected root boundary"
    )
  end

  defp scope_diagnostic(relative) do
    Diagnostic.new!(
      level: :error,
      phase: :discovery,
      code: :path_outside_root,
      message: "discovered source is outside the selected root: #{relative}"
    )
  end

  defp file_diagnostic(relative, code, reason) do
    Diagnostic.new!(
      level: :error,
      phase: :discovery,
      code: code,
      file: if(Span.valid_file?(relative), do: relative),
      message: "source file operation failed: #{inspect(reason)}"
    )
  end

  defp sort_diagnostics(diagnostics) do
    Enum.sort_by(diagnostics, &{&1.level, &1.phase, &1.file || "", &1.code})
  end
end
