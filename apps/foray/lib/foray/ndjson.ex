defmodule Foray.NDJSON do
  @moduledoc "Streaming parser for ffuf v2.2 `-json` newline-delimited output."

  alias Foray.{Match, OutputError}

  @required_integer_fields ~w(position status length words lines duration)
  @required_string_fields ~w(content-type redirectlocation url resultfile host)

  @doc "Parses partial binary chunks into validated match structs."
  @spec stream(Enumerable.t()) :: Enumerable.t(Match.t())
  def stream(chunks), do: Foray.LineStream.transform(chunks, &parse_line/1)

  @doc "Parses one complete ffuf NDJSON line. Blank lines are ignored."
  @spec parse_line(String.t()) :: {:ok, Match.t()} | :ignore | {:error, OutputError.t()}
  def parse_line(line) when is_binary(line) do
    with {:ok, line} <- Foray.LineStream.check_line(line) do
      case String.trim(line) do
        "" -> :ignore
        line -> decode_line(line)
      end
    end
  end

  defp decode_line(line) do
    with {:ok, record} when is_map(record) <- Jason.decode(line),
         :ok <- validate_fields(record),
         {:ok, input} <- decode_input(record["input"]) do
      {:ok,
       %Match{
         input: input,
         position: record["position"],
         status: record["status"],
         length: record["length"],
         words: record["words"],
         lines: record["lines"],
         content_type: record["content-type"],
         redirect_location: record["redirectlocation"],
         url: record["url"],
         duration_ns: record["duration"],
         scraper: record["scraper"],
         result_file: record["resultfile"],
         host: record["host"],
         raw: record
       }}
    else
      {:error, %Jason.DecodeError{} = reason} ->
        output_error(line, {:invalid_json, Exception.message(reason)})

      {:error, reason} ->
        output_error(line, reason)

      _other ->
        output_error(line, :expected_json_object)
    end
  end

  defp validate_fields(record) do
    integers_valid? =
      Enum.all?(@required_integer_fields, fn field ->
        value = record[field]
        is_integer(value) and value >= 0
      end)

    strings_valid? = Enum.all?(@required_string_fields, &is_binary(record[&1]))

    cond do
      not is_map(record["input"]) -> {:error, {:invalid_field, "input"}}
      not integers_valid? -> {:error, :invalid_integer_field}
      not strings_valid? -> {:error, :invalid_string_field}
      not is_map(record["scraper"]) -> {:error, {:invalid_field, "scraper"}}
      true -> :ok
    end
  end

  defp decode_input(input) do
    Enum.reduce_while(input, {:ok, %{}}, fn
      {keyword, encoded}, {:ok, acc} when is_binary(keyword) and is_binary(encoded) ->
        case Base.decode64(encoded) do
          {:ok, value} -> {:cont, {:ok, Map.put(acc, keyword, value)}}
          :error -> {:halt, {:error, {:invalid_base64_input, keyword}}}
        end

      {keyword, _value}, _acc ->
        {:halt, {:error, {:invalid_input, keyword}}}
    end)
  end

  defp output_error(line, reason), do: {:error, OutputError.exception(line: line, reason: reason)}
end
