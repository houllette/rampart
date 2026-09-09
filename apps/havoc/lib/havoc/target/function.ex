defmodule Havoc.Target.Function do
  @moduledoc """
  Derives fuzzable public function arguments from runtime `@spec` metadata.

  Derivation is intentionally conservative. Havoc currently recognizes direct
  `String.t()` and `binary()` arguments, including unions containing either.
  Opaque/local aliases and structured request types are skipped rather than
  guessed. Callers can add explicit one-based argument positions with the
  `:parameters` option.
  """

  @behaviour Havoc.Target.Provider

  alias Havoc.Target

  @schema [
    only: [type: {:list, {:or, [:atom, {:tuple, [:atom, :non_neg_integer]}]}}, default: []],
    except: [type: {:list, {:or, [:atom, {:tuple, [:atom, :non_neg_integer]}]}}, default: []],
    parameters: [type: {:map, :any, :any}, default: %{}],
    generator: [type: :any],
    oracles: [type: {:list, :any}, default: [:no_crash]],
    classes: [type: {:list, :atom}, default: [:derived, :function_input]]
  ]

  @impl true
  def derive(module, opts \\ []) when is_atom(module) do
    ensure_module_loaded!(module)
    opts = NimbleOptions.validate!(opts, @schema)
    generator = Keyword.get_lazy(opts, :generator, &Havoc.Gen.all/0)

    module
    |> fetch_specs!()
    |> Enum.flat_map(&targets_for_spec(module, &1, opts, generator))
    |> Enum.uniq_by(& &1.id)
    |> Enum.sort_by(& &1.id)
  end

  @doc "Invokes a derived function target after replacing its selected argument."
  @spec invoke(Target.t(), payload :: term(), opts :: keyword()) :: term()
  def invoke(
        %Target{kind: :function, module: module, function: function} = target,
        payload,
        opts \\ []
      ) do
    arguments = arguments!(target, Keyword.get(opts, :arguments))
    position = target.meta.parameter_position
    apply(module, function, List.replace_at(arguments, position - 1, payload))
  end

  defp ensure_module_loaded!(module) do
    case Code.ensure_loaded(module) do
      {:module, ^module} ->
        :ok

      {:error, reason} ->
        raise ArgumentError, "cannot load #{inspect(module)}: #{inspect(reason)}"
    end
  end

  defp fetch_specs!(module) do
    case Code.Typespec.fetch_specs(module) do
      {:ok, specs} -> specs
      :error -> raise ArgumentError, "#{inspect(module)} has no readable BEAM specs"
    end
  end

  defp targets_for_spec(module, {{name, arity}, forms}, opts, generator) do
    if function_exported?(module, name, arity) and selected?({name, arity}, opts) do
      inferred = Enum.flat_map(forms, &positions_from_form(name, &1))
      explicit = explicit_positions(opts[:parameters], name, arity)

      (inferred ++ explicit)
      |> Enum.uniq()
      |> Enum.sort()
      |> Enum.map(&build_target(module, name, arity, &1, generator, opts))
    else
      []
    end
  end

  defp positions_from_form(name, form) do
    case Code.Typespec.spec_to_quoted(name, form) do
      {:"::", _, [{^name, _, arguments}, _return]} when is_list(arguments) ->
        arguments
        |> Enum.with_index(1)
        |> Enum.flat_map(&text_position/1)

      _other ->
        []
    end
  end

  defp text_position({argument, position}) do
    if text_type?(argument_type(argument)), do: [position], else: []
  end

  defp argument_type({:"::", _, [_name, type]}), do: type
  defp argument_type(type), do: type

  defp text_type?({:binary, _, []}), do: true
  defp text_type?({{:., _, [String, :t]}, _, []}), do: true
  defp text_type?({:|, _, [left, right]}), do: text_type?(left) or text_type?(right)
  defp text_type?(_type), do: false

  defp explicit_positions(parameters, name, arity) do
    positions = Map.get(parameters, {name, arity}, Map.get(parameters, name, []))

    Enum.map(positions, fn position ->
      if is_integer(position) and position >= 1 and position <= arity do
        position
      else
        raise ArgumentError,
              "invalid one-based parameter position #{inspect(position)} for #{name}/#{arity}"
      end
    end)
  end

  defp selected?({name, _arity} = mfa, opts) do
    included = opts[:only] == [] or name in opts[:only] or mfa in opts[:only]
    excluded = name in opts[:except] or mfa in opts[:except]
    included and not excluded
  end

  defp build_target(module, name, arity, position, generator, opts) do
    module_name = module |> Atom.to_string() |> String.trim_leading("Elixir.")
    id = "function:#{module_name}.#{name}/#{arity}:arg#{position}"

    %Target{
      id: id,
      kind: :function,
      generator: generator,
      module: module,
      function: name,
      arity: arity,
      parameter: position,
      oracles: opts[:oracles],
      classes: opts[:classes],
      locus: %{module: module_name, function: "#{name}/#{arity}", param: position},
      meta: %{provider: :typespec, parameter_position: position}
    }
  end

  defp arguments!(%Target{arity: 1}, nil), do: [nil]

  defp arguments!(target, resolver) when is_function(resolver, 1) do
    arguments!(target, resolver.(target))
  end

  defp arguments!(%Target{arity: arity}, arguments) when is_list(arguments) do
    if length(arguments) == arity do
      arguments
    else
      raise ArgumentError, "expected #{arity} invocation arguments, got #{length(arguments)}"
    end
  end

  defp arguments!(target, nil) do
    raise ArgumentError,
          "arguments: is required to invoke derived #{target.function}/#{target.arity} target"
  end

  defp arguments!(_target, other) do
    raise ArgumentError,
          "arguments: must be a list or one-argument resolver, got: #{inspect(other)}"
  end
end
