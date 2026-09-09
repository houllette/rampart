defmodule MuexSecurity.Mutator.SanitizerBypass do
  @moduledoc "Replaces narrowly named sanitizer/redaction calls with their raw first input."

  @behaviour Muex.Mutator

  alias MuexSecurity.Mutation

  @sanitizers [
    :sanitize,
    :sanitize_html,
    :html_escape,
    :escape_html,
    :strip_tags,
    :redact,
    :redact_secret,
    :mask_secret,
    :filter_input,
    :clean_html
  ]

  @impl true
  def name, do: "SanitizerBypass"

  @impl true
  def description, do: "Passes raw input around sanitizer and redaction calls"

  @impl true
  def supported_languages, do: [Muex.Language.Elixir]

  @impl true
  def mutate({{:., _dot_metadata, [_receiver, name]}, metadata, [input | _rest]}, context)
      when name in @sanitizers do
    [Mutation.build(__MODULE__, input, "bypass #{name}", context, metadata)]
  end

  def mutate(_ast, _context), do: []
end
