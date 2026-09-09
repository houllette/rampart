defmodule RampartSAST.RulesTest do
  use ExUnit.Case, async: true

  alias RampartSAST.{Context, ContextProvider, Source}
  alias RampartSAST.Rules.{DynamicCode, UnsafeAtom, UnsafeDeserialization, UnsafeExec}

  test "unsafe atom rule distinguishes dynamic input and pipeline arity from literals" do
    source =
      source!("""
      defmodule Example do
        def direct(input), do: String.to_atom(input)
        def piped(input), do: input |> String.to_atom()
        def bounded, do: String.to_atom("fixed")
      end
      """)

    matches = UnsafeAtom.run_source(source, %Context{}, [])

    assert length(matches) == 2
    assert Enum.all?(matches, &(&1.facts.input_shape == :dynamic))
    assert Enum.any?(matches, & &1.facts.piped)
    assert Enum.all?(matches, &(&1.facts.api == "String.to_atom/1"))
  end

  test "unsafe exec rule excludes argument-vector System.cmd calls" do
    source =
      source!("""
      defmodule Example do
        def shell(command), do: System.shell(command)
        def os, do: :os.cmd("date")
        def vector(command), do: System.cmd("echo", [command])
      end
      """)

    matches = UnsafeExec.run_source(source, %Context{}, [])

    assert Enum.map(matches, & &1.facts.api) == ["System.shell/1", ":os.cmd/1"]
    assert Enum.map(matches, & &1.confidence) == [:medium, :low]
  end

  test "pipeline normalization does not also report its unexpanded right-hand call" do
    source =
      source!("""
      defmodule Example do
        def shell(command), do: command |> System.shell(env: [{"LANG", "C"}])
      end
      """)

    assert [match] = UnsafeExec.run_source(source, %Context{}, [])
    assert match.facts.api == "System.shell/2"
    assert match.facts.piped
  end

  test "deserialization rule records :safe as a qualification, not a suppression" do
    source =
      source!("""
      defmodule Example do
        def decode(binary), do: :erlang.binary_to_term(binary, [:safe])
      end
      """)

    assert [match] = UnsafeDeserialization.run_source(source, %Context{}, [])
    assert match.facts.safe_option

    assert match.facts.safe_option_effect ==
             :limits_atom_creation_but_does_not_prove_trusted_input

    assert match.confidence == :medium
  end

  test "dynamic code rule records literal versus dynamic evaluated input" do
    source =
      source!("""
      defmodule Example do
        def dynamic(code), do: Code.eval_string(code)
        def fixed, do: EEx.eval_string("<%= 1 + 1 %>")
      end
      """)

    matches = DynamicCode.run_source(source, %Context{}, [])

    assert Enum.map(matches, & &1.facts.input_shape) == [:dynamic, :literal]
    assert Enum.map(matches, & &1.confidence) == [:medium, :low]
  end

  test "Elixir context provider namespaces structural and Phoenix role facts" do
    controller =
      source!(
        """
        defmodule ExampleWeb.UserController do
          alias Ecto.Adapters.SQL, as: SQL
          import Plug.Conn
          use ExampleWeb, :controller
        end
        """,
        "lib/example_web/user_controller.ex"
      )

    router =
      source!(
        """
        defmodule ExampleWeb.Router do
          use Phoenix.Router
        end
        """,
        "lib/example_web/router.ex"
      )

    assert {context, []} =
             ContextProvider.build([controller, router], [RampartSAST.Context.Elixir])

    controller_facts =
      Context.source_facts(
        context,
        "rampart.elixir-context.v1",
        "lib/example_web/user_controller.ex"
      )

    project_facts = Context.project_facts(context, "rampart.elixir-context.v1")

    assert controller_facts.aliases["SQL"] == "Ecto.Adapters.SQL"
    assert controller_facts.imports == ["Plug.Conn"]
    assert :phoenix_controller in controller_facts.roles
    assert project_facts.phoenix_routers == ["lib/example_web/router.ex"]
    assert project_facts.phoenix_controllers == ["lib/example_web/user_controller.ex"]
  end

  defp source!(content, path \\ "lib/example.ex") do
    assert {:ok, source, _diagnostics} = Source.parse(path, content, 100_000)
    source
  end
end
