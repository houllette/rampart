defmodule HavocProper.Case do
  @moduledoc "Imports the experimental coverage-guided ExUnit property macro."

  defmacro __using__(_opts) do
    quote do
      import HavocProper.Case, only: [guided_security_property: 3]
      import Havoc.Case, only: [havoc_assert: 2, havoc_assert: 3]
    end
  end

  @doc "Defines a non-async coverage-guided security property backed by PropEr."
  defmacro guided_security_property(name, opts, do: body) do
    caller_module = __CALLER__.module

    quote do
      ExUnit.Case.test unquote(name) do
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

        HavocProper.Guided.check!(generator, property_options, fn generated_payload ->
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
end
