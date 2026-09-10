defmodule Foray.Finding do
  @moduledoc "Projects validated ffuf matches into Rampart's normalized finding contract."

  alias Foray.{FuzzPoint, Job, Match, Target, Wordlist}

  @doc "Builds one independently triageable finding from an ffuf match."
  @spec from_match(Match.t(), Job.t()) :: Core.Finding.t()
  def from_match(%Match{} = match, %Job{} = job) do
    point = primary_point(job.fuzz_points, match.input)
    point_name = point_name(point)
    category = category(point)
    url = normalize_url(match.url)
    {keyword, input} = primary_input(match.input, point)

    struct(Core.Finding,
      id:
        Core.Finding.dedupe_id(:foray, [
          "http_match_v3",
          job.method,
          url,
          category,
          point_name,
          input_signature(match.input, job.wordlists)
        ]),
      source: :foray,
      category: category,
      locus: %{
        url: url,
        method: job.method,
        host: match.host,
        param: point_name,
        keyword: keyword,
        input: input,
        status: match.status,
        length: match.length,
        words: match.words,
        lines: match.lines,
        content_type: match.content_type,
        identity_version: 3
      },
      severity: nil,
      confidence: :medium,
      evidence: evidence(match, keyword, input),
      raw: match.raw,
      seed: seed_for(job, match.input),
      observed_at: DateTime.utc_now()
    )
  end

  defp seed_for(%Job{seed_index: nil, wordlists: wordlists}, inputs),
    do: Wordlist.seed_for(wordlists, inputs)

  defp seed_for(%Job{seed_index: index}, inputs), do: Wordlist.indexed_seed(index, inputs)

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

  defp input_signature(input, wordlists) do
    input
    |> Map.take(Enum.map(wordlists, & &1.keyword))
    |> Enum.sort()
    |> :erlang.term_to_binary([:deterministic])
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
