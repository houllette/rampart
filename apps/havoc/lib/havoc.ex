defmodule Havoc do
  @moduledoc """
  ExUnit-integrated adversarial generation, conservative security oracles, and
  durable concrete counterexamples.

  Havoc runs in the caller's test VM. It does not launch external programs and
  intentionally does not use `Core.Runner` or `Core.Scope`.
  """

  alias Core.Seed
  alias Havoc.TermCodec

  @doc "Returns true when the process-wide replay-only mode is enabled."
  @spec corpus_only?() :: boolean()
  def corpus_only? do
    System.get_env("HAVOC_MODE") == "corpus_only" or
      Application.get_env(:havoc, :mode, :full) == :corpus_only
  end

  @doc "Returns Havoc's versioned, machine-discoverable validation actions."
  @spec validation_actions() :: [Core.Validation.Action.t()]
  def validation_actions, do: Core.Validation.actions(Havoc.Validator)

  @doc "Validates one concrete seed or finding seed against a target and oracle set."
  @spec validate(
          Core.Seed.t() | Core.Finding.t(),
          target :: (term() -> term()),
          property_options :: keyword()
        ) :: Core.Validation.Result.t()
  def validate(subject, target, property_options \\ [])
      when is_function(target, 1) and is_list(property_options) do
    request = Core.Validation.request(Havoc.Validator.action(), subject)

    Core.Validation.run(Havoc.Validator, request,
      target: target,
      property_options: property_options
    )
  end

  @doc "Promotes a suite finding-derived value into a Havoc-compatible Core seed."
  @spec promote(Core.Finding.t(), value :: term(), opts :: keyword()) :: Seed.t()
  def promote(%Core.Finding{} = finding, value, opts \\ []) do
    unless is_atom(finding.source) and is_binary(finding.id) and finding.id != "" do
      raise ArgumentError, "promoted findings require a source and non-empty id"
    end

    schema = [classes: [type: {:list, :atom}, default: []], meta: [type: :map, default: %{}]]
    opts = NimbleOptions.validate!(opts, schema)

    %Seed{
      id:
        Core.Finding.dedupe_id(:havoc, [
          "promoted_seed",
          finding.source,
          finding.id,
          TermCodec.fingerprint(value)
        ]),
      value: value,
      classes: opts[:classes],
      provenance: :promoted_finding,
      origin: {finding.source, finding.id},
      meta: opts[:meta]
    }
  end
end
