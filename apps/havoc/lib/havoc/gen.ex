defmodule Havoc.Gen do
  @moduledoc """
  Adversarial generators built directly from StreamData combinators.

  The built-in payloads are deliberately inert: they contain markers and
  non-destructive probes, no destructive shell or SQL commands, cloud metadata
  addresses, or live callback hosts.
  """

  alias Core.Seed
  alias Havoc.Corpus

  @doc "Generates payloads from one or more injection classes, with light semantic mutations."
  @spec injection(classes :: [atom()], opts :: keyword()) :: StreamData.t(String.t())
  def injection(classes, opts \\ []) when is_list(classes) do
    schema = [mutate: [type: :boolean, default: true]]
    opts = NimbleOptions.validate!(opts, schema)
    validate_injection_classes!(classes)

    base =
      classes
      |> Enum.flat_map(&Corpus.builtin/1)
      |> Enum.map(& &1.value)
      |> StreamData.member_of()

    if opts[:mutate], do: mutated(base), else: base
  end

  @doc "Adds bounded whitespace, casing, duplication, and URL-encoding mutations."
  @spec mutated(generator :: StreamData.t(String.t())) :: StreamData.t(String.t())
  def mutated(generator) do
    mutations =
      StreamData.bind(generator, fn payload ->
        payload
        |> mutations_for()
        |> StreamData.member_of()
      end)

    StreamData.one_of([generator, mutations])
  end

  @doc "Generates invalid UTF-8, embedded null bytes, and malformed byte sequences."
  @spec malformed() :: StreamData.t(binary())
  def malformed do
    :null_byte
    |> Corpus.builtin()
    |> Kernel.++(Corpus.builtin(:malformed_utf8))
    |> Enum.map(& &1.value)
    |> StreamData.member_of()
  end

  @doc "Generates bounded-size, overflow-adjacent, and format-string inputs."
  @spec boundary(opts :: keyword()) :: StreamData.t(String.t())
  def boundary(opts \\ []) do
    schema = [max_length: [type: :pos_integer, default: 16_384]]
    opts = NimbleOptions.validate!(opts, schema)
    max_length = opts[:max_length]

    values =
      [
        "",
        "0",
        "-1",
        Integer.to_string(2_147_483_647),
        Integer.to_string(2_147_483_648),
        Integer.to_string(9_223_372_036_854_775_807),
        String.duplicate("A", max_length)
      ] ++ Enum.map(Corpus.builtin(:format_string), & &1.value)

    StreamData.member_of(values)
  end

  @doc "Combines injection and structural adversarial generators."
  @spec all(opts :: keyword()) :: StreamData.t(binary())
  def all(opts \\ []) do
    schema = [
      classes: [type: {:list, :atom}, default: Corpus.injection_classes()],
      max_length: [type: :pos_integer, default: 16_384]
    ]

    opts = NimbleOptions.validate!(opts, schema)

    StreamData.one_of([
      injection(opts[:classes]),
      malformed(),
      boundary(max_length: opts[:max_length])
    ])
  end

  @doc "Mixes imported or persisted Core seed values into another generator."
  @spec with_corpus(generator :: StreamData.t(term()), seeds :: Enumerable.t()) ::
          StreamData.t(term())
  def with_corpus(generator, seeds) do
    values =
      Enum.map(seeds, fn
        %Seed{value: value} -> value
        value -> value
      end)

    case values do
      [] -> generator
      [_first | _rest] -> StreamData.one_of([StreamData.member_of(values), generator])
    end
  end

  defp validate_injection_classes!([]) do
    raise ArgumentError, "at least one injection class is required"
  end

  defp validate_injection_classes!(classes) do
    unknown = classes -- Corpus.injection_classes()

    if unknown != [] do
      raise ArgumentError, "unknown injection classes: #{inspect(unknown)}"
    end
  end

  defp mutations_for(payload) do
    [
      payload,
      " " <> payload,
      payload <> " ",
      payload <> payload,
      String.upcase(payload),
      URI.encode_www_form(payload)
    ]
    |> Enum.uniq()
  end
end
