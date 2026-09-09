defmodule RampartSAST.ModuleOwners do
  @moduledoc "Derives module-to-package ownership from bounded BEAM artifacts without loading modules."

  import Bitwise

  @default_max_beam_bytes 5_000_000
  @default_max_modules 25_000
  @default_max_total_bytes 100_000_000

  @doc "Reads bounded BEAM paths and returns only unambiguous module ownership."
  @spec from_paths!([{package :: String.t(), Path.t()}], keyword()) :: %{String.t() => String.t()}
  def from_paths!(entries, options \\ []) when is_list(entries) and is_list(options) do
    options = limits(options)
    enforce_module_count!(entries, options[:max_modules])

    {paths, total_bytes} =
      Enum.map_reduce(entries, 0, fn entry, total ->
        {package, path, size} = validate_path_entry!(entry, options[:max_beam_bytes])
        {{package, path}, total + size}
      end)

    enforce_total_bytes!(total_bytes, options[:max_total_bytes])

    binaries = Enum.map(paths, fn {package, path} -> {package, File.read!(path)} end)
    from_binaries!(binaries, options)
  end

  @doc "Parses bounded BEAM binaries and returns only unambiguous module ownership."
  @spec from_binaries!([{package :: String.t(), binary()}], keyword()) ::
          %{String.t() => String.t()}
  def from_binaries!(entries, options \\ []) when is_list(entries) and is_list(options) do
    options = limits(options)
    enforce_module_count!(entries, options[:max_modules])

    total_bytes =
      Enum.reduce(entries, 0, fn entry, total ->
        {_package, beam} = validate_binary_entry!(entry, options[:max_beam_bytes])
        total + byte_size(beam)
      end)

    enforce_total_bytes!(total_bytes, options[:max_total_bytes])

    entries
    |> Enum.reduce(%{}, fn {package, beam}, candidates ->
      module = beam_module!(beam)
      Map.update(candidates, module, MapSet.new([package]), &MapSet.put(&1, package))
    end)
    |> Enum.flat_map(fn {module, packages} ->
      if MapSet.size(packages) == 1, do: [{module, Enum.at(packages, 0)}], else: []
    end)
    |> Map.new()
  end

  defp limits(options) do
    options =
      Keyword.validate!(options,
        max_beam_bytes: @default_max_beam_bytes,
        max_modules: @default_max_modules,
        max_total_bytes: @default_max_total_bytes
      )

    unless is_integer(options[:max_beam_bytes]) and options[:max_beam_bytes] > 0 and
             is_integer(options[:max_modules]) and options[:max_modules] > 0 and
             is_integer(options[:max_total_bytes]) and options[:max_total_bytes] > 0 do
      raise ArgumentError, "BEAM inventory limits must be positive integers"
    end

    options
  end

  defp validate_path_entry!({package, path} = entry, max_beam_bytes) when is_binary(path) do
    validate_package!(package, entry, :path)

    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} when size <= max_beam_bytes ->
        {package, path, size}

      {:ok, %File.Stat{type: :regular}} ->
        raise ArgumentError, "BEAM artifact exceeds the configured byte limit"

      _other ->
        raise ArgumentError, "BEAM artifact path must identify a regular file"
    end
  end

  defp validate_path_entry!(entry, _max_beam_bytes) do
    raise ArgumentError, "invalid package/BEAM path entry: #{inspect(entry)}"
  end

  defp validate_binary_entry!({package, beam} = entry, max_beam_bytes) when is_binary(beam) do
    validate_package!(package, entry, :binary)

    if byte_size(beam) <= max_beam_bytes,
      do: {package, beam},
      else: raise(ArgumentError, "BEAM artifact exceeds the configured byte limit")
  end

  defp validate_binary_entry!(entry, _max_beam_bytes) do
    raise ArgumentError, "invalid package/BEAM binary entry: #{inspect(entry)}"
  end

  defp validate_package!(package, _entry, _entry_type)
       when is_binary(package) and byte_size(package) > 0 do
    if String.trim(package) == "",
      do: raise(ArgumentError, "BEAM package names must not be blank")
  end

  defp validate_package!(_package, entry, :path) do
    raise ArgumentError, "invalid package/BEAM path entry: #{inspect(entry)}"
  end

  defp validate_package!(_package, entry, :binary) do
    raise ArgumentError, "invalid package/BEAM binary entry: #{inspect(entry)}"
  end

  defp enforce_module_count!(entries, max_modules) do
    if length(entries) > max_modules,
      do: raise(ArgumentError, "BEAM module count exceeds the configured limit")
  end

  defp enforce_total_bytes!(total_bytes, max_total_bytes) do
    if total_bytes > max_total_bytes,
      do: raise(ArgumentError, "BEAM artifacts exceed the configured total byte limit")
  end

  defp beam_module!(<<"FOR1", declared_size::unsigned-big-32, "BEAM", chunks::binary>> = beam) do
    if declared_size < 4 or declared_size + 8 != byte_size(beam),
      do: raise(ArgumentError, "invalid BEAM artifact size")

    chunks
    |> find_atom_chunk()
    |> first_atom!()
  end

  defp beam_module!(_beam), do: raise(ArgumentError, "invalid BEAM artifact header")

  defp find_atom_chunk(<<id::binary-size(4), size::unsigned-big-32, rest::binary>>) do
    padding = rem(4 - rem(size, 4), 4)

    case rest do
      <<chunk::binary-size(^size), _padding::binary-size(^padding), remaining::binary>> ->
        if id in ["Atom", "AtU8"], do: {id, chunk}, else: find_atom_chunk(remaining)

      _truncated ->
        raise ArgumentError, "truncated BEAM chunk"
    end
  end

  defp find_atom_chunk(<<>>), do: raise(ArgumentError, "BEAM artifact has no atom table")
  defp find_atom_chunk(_truncated), do: raise(ArgumentError, "truncated BEAM chunk header")

  defp first_atom!({encoding, <<count::signed-big-32, rest::binary>>}) when count != 0 do
    {length, rest} = atom_length!(count, rest)

    case rest do
      <<module::binary-size(^length), _remaining::binary>> ->
        module = decode_module_name(module, encoding)

        if String.valid?(module) and module != "",
          do: module,
          else: raise(ArgumentError, "BEAM module name is not valid text")

      _truncated ->
        raise ArgumentError, "truncated BEAM atom table"
    end
  end

  defp first_atom!(_chunk), do: raise(ArgumentError, "invalid BEAM atom table")

  defp atom_length!(count, <<length, rest::binary>>) when count > 0, do: {length, rest}

  defp atom_length!(count, <<encoded, rest::binary>>) when count < 0 do
    if (encoded &&& 0x08) == 0 do
      {encoded >>> 4, rest}
    else
      case rest do
        <<low, remaining::binary>> -> {(encoded &&& 0xE0) <<< 3 ||| low, remaining}
        _truncated -> raise ArgumentError, "truncated BEAM compact atom length"
      end
    end
  end

  defp atom_length!(_count, _rest), do: raise(ArgumentError, "invalid BEAM atom length")

  defp decode_module_name(module, "AtU8"), do: module

  defp decode_module_name(module, "Atom"),
    do: :unicode.characters_to_binary(module, :latin1, :utf8)
end
