defmodule Foray.Finding do
  @moduledoc "Projects validated ffuf matches into Rampart's normalized finding contract."

  alias Foray.{FuzzPoint, Job, Match, Target, Wordlist}

  @doc "Builds one independently triageable finding from an ffuf match."
  @spec from_match(Match.t(), Job.t()) :: Core.Finding.t()
  def from_match(%Match{} = match, %Job{} = job) do
    point = primary_point(job.fuzz_points, match.input)
    category = category(point)
    url = normalize_url(match.url)
    {keyword, input} = primary_input(match.input, point)

    struct(Core.Finding,
      id:
        Core.Finding.dedupe_id(:foray, [
          "http_match",
          job.method,
          url,
          category,
          point_name(point),
          input_signature(match.input)
        ]),
      source: :foray,
      category: category,
      locus: %{
        url: url,
        method: job.method,
        host: match.host,
        param: point_name(point),
        keyword: keyword,
        input: input,
        status: match.status,
        length: match.length,
        words: match.words,
        lines: match.lines,
        content_type: match.content_type
      },
      severity: nil,
      confidence: :medium,
      evidence: evidence(match, keyword, input),
      raw: match.raw,
      seed: Wordlist.seed_for(job.wordlists, match.input),
      observed_at: DateTime.utc_now()
    )
  end

  defp primary_point(points, input) do
    matching = Enum.filter(points, &Map.has_key?(input, &1.keyword))

    Enum.find(matching, &vhost?/1) ||
      Enum.find(matching, &(&1.location in [:query, :body, :cookie])) ||
      List.first(matching) || List.first(points)
  end

  defp category(point) do
    cond do
      vhost?(point) ->
        :vhost

      match?(%FuzzPoint{location: location} when location in [:query, :body, :cookie], point) ->
        :param_injection

      match?(%FuzzPoint{location: :url}, point) ->
        :exposed_path

      true ->
        :matched_response
    end
  end

  defp vhost?(%FuzzPoint{location: :header, name: name}) when is_binary(name) do
    String.downcase(name) == "host"
  end

  defp vhost?(_point), do: false

  defp point_name(%FuzzPoint{name: name}) when is_binary(name), do: name
  defp point_name(%FuzzPoint{location: location}), do: Atom.to_string(location)
  defp point_name(_point), do: nil

  defp primary_input(input, %FuzzPoint{keyword: keyword}) do
    {keyword, Map.get(input, keyword)}
  end

  defp primary_input(input, _point), do: input |> Enum.sort() |> List.first() || {nil, nil}

  defp input_signature(input) do
    input
    |> Enum.sort()
    |> Enum.map_join("\u0000", fn {keyword, value} -> keyword <> "=" <> value end)
  end

  defp normalize_url(url) do
    case Target.parse(url) do
      {:ok, target} -> target.url
      {:error, _reason} -> url
    end
  end

  defp evidence(match, nil, _input), do: "matched HTTP #{match.status}, length=#{match.length}"

  defp evidence(match, keyword, input) do
    "matched HTTP #{match.status}, length=#{match.length}, #{keyword}=#{inspect(input)}"
  end
end
