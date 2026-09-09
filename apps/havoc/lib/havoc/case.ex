defmodule Havoc.Case do
  @moduledoc "Imports Havoc's ExUnit property macro, assertion macro, and adversarial generators."

  defmacro __using__(_opts) do
    quote do
      use ExUnitProperties

      import Havoc.Case,
        only: [security_property: 3, security_targets: 3, havoc_assert: 2, havoc_assert: 3]

      import Havoc.Gen
    end
  end

  @doc "Defines an ExUnit property backed by StreamData and Havoc's persistent corpus."
  defmacro security_property(name, opts, do: body) do
    caller_module = __CALLER__.module

    quote do
      ExUnitProperties.property unquote(name) do
        havoc_options = unquote(opts)
        generator = Keyword.fetch!(havoc_options, :generator)
        declared_oracles = Keyword.get(havoc_options, :oracles, [:no_crash])
        property_name = unquote(name)

        property_options =
          havoc_options
          |> Keyword.delete(:generator)
          |> Keyword.put_new(:property_name, property_name)
          |> Keyword.put_new(:property_id, "#{inspect(unquote(caller_module))}:#{property_name}")
          |> Keyword.put_new(:module, unquote(caller_module))

        Havoc.Property.check!(generator, property_options, fn generated_payload ->
          var!(payload) = generated_payload
          var!(havoc_oracles, Havoc.Case) = declared_oracles

          var!(havoc_oracle_context, Havoc.Case) =
            Keyword.get(havoc_options, :oracle_context, %{})

          observation = unquote(body)
          _payload_was_bound = var!(payload)
          observation
        end)
      end
    end
  end

  @doc "Defines one ExUnit property that evaluates a collection of derived targets."
  defmacro security_targets(name, opts, do: body) do
    caller_module = __CALLER__.module

    quote do
      ExUnitProperties.property unquote(name) do
        havoc_options = unquote(opts)
        targets = Keyword.fetch!(havoc_options, :targets)
        property_name = unquote(name)

        property_options =
          havoc_options
          |> Keyword.delete(:targets)
          |> Keyword.put_new(:property_name, property_name)
          |> Keyword.put_new(:property_id, "#{inspect(unquote(caller_module))}:#{property_name}")
          |> Keyword.put_new(:module, unquote(caller_module))

        Havoc.Target.check_all!(targets, property_options, fn
          generated_target, generated_payload, declared_oracles, oracle_context ->
            var!(target) = generated_target
            var!(payload) = generated_payload
            var!(havoc_oracles, Havoc.Case) = declared_oracles
            var!(havoc_oracle_context, Havoc.Case) = oracle_context
            observation = unquote(body)
            _target_was_bound = var!(target)
            _payload_was_bound = var!(payload)
            observation
        end)
      end
    end
  end

  @doc "Runs the security property's declared oracles against an observation."
  defmacro havoc_assert(observation, payload) do
    quote do
      Havoc.Oracle.assert!(
        var!(havoc_oracles, Havoc.Case),
        unquote(observation),
        unquote(payload),
        var!(havoc_oracle_context, Havoc.Case)
      )
    end
  end

  @doc "Runs declared oracles with an explicit per-observation context map."
  defmacro havoc_assert(observation, payload, context) do
    quote do
      Havoc.Oracle.assert!(
        var!(havoc_oracles, Havoc.Case),
        unquote(observation),
        unquote(payload),
        unquote(context)
      )
    end
  end
end
