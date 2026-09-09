defmodule MuexSecurity.MutatorsTest do
  use ExUnit.Case, async: true

  alias Muex.{Compiler, Language}
  alias MuexSecurity.Mutator

  @context %{file: "lib/example.ex", line: 7}

  test "security decision mutator forces allow and deny predicates toward bypass" do
    [allow] =
      Mutator.SecurityDecision.mutate(quote(do: Policy.authorized?(actor, resource)), @context)

    [deny] = Mutator.SecurityDecision.mutate(quote(do: Token.revoked?(token)), @context)

    assert allow.ast == true
    assert deny.ast == false
    assert allow.location.file == "lib/example.ex"
    assert allow.mutator == Mutator.SecurityDecision
    assert Mutator.SecurityDecision.mutate(quote(do: Changeset.valid?(changeset)), @context) == []
  end

  test "sanitizer bypass returns the unsanitized first argument" do
    [mutation] =
      Mutator.SanitizerBypass.mutate(quote(do: HTML.sanitize_html(input, mode)), @context)

    assert Macro.to_string(mutation.ast) == "input"
    assert mutation.description =~ "bypass sanitize_html"
    assert Mutator.SanitizerBypass.mutate(quote(do: URI.encode(input)), @context) == []
  end

  test "secure compare mutator downgrades only recognized comparison calls" do
    [plug] =
      Mutator.SecureCompare.mutate(quote(do: Plug.Crypto.secure_compare(left, right)), @context)

    [crypto] = Mutator.SecureCompare.mutate(quote(do: :crypto.hash_equals(left, right)), @context)

    assert Macro.to_string(plug.ast) == "left == right"
    assert Macro.to_string(crypto.ast) == "left == right"
    assert Mutator.SecureCompare.mutate(quote(do: Other.compare(left, right)), @context) == []
  end

  test "security header mutator removes only recognized static header writes" do
    [mutation] =
      Mutator.SecurityHeader.mutate(
        quote(do: Plug.Conn.put_resp_header(conn, "Content-Security-Policy", policy)),
        @context
      )

    assert Macro.to_string(mutation.ast) == "conn"

    assert Mutator.SecurityHeader.mutate(
             quote(do: Plug.Conn.put_resp_header(conn, "cache-control", "no-store")),
             @context
           ) == []
  end

  test "transport mutator weakens explicit TLS verification options" do
    [peer] = Mutator.TransportSecurity.mutate({:verify, :verify_peer}, @context)
    [hostname] = Mutator.TransportSecurity.mutate({:check_hostname, true}, @context)

    assert peer.ast == {:verify, :verify_none}
    assert hostname.ast == {:check_hostname, false}
    assert peer.location.line == 7
  end

  test "configures Muex with all operators or a named subset without recompiling sources" do
    assert {:ok, all_config} =
             MuexSecurity.configure(["--files", "lib", "--test-paths", "test"])

    assert Enum.sort(all_config.mutators) == Enum.sort(Map.values(MuexSecurity.mutators()))

    assert {:ok, selected_config} =
             MuexSecurity.configure([
               "--mutators=secure_compare,security_header",
               "--files",
               "lib"
             ])

    assert selected_config.mutators == [Mutator.SecureCompare, Mutator.SecurityHeader]

    assert {:error, "unknown security mutator: unknown"} =
             MuexSecurity.configure(["--mutators", "unknown"])
  end

  test "call mutators skip indistinguishable local function definition heads" do
    ast =
      quote line: 20 do
        def authorized?(actor, resource), do: actor == resource
        def sanitize_html(input), do: input
      end

    mutations =
      Muex.Mutator.walk(
        ast,
        [Mutator.SecurityDecision, Mutator.SanitizerBypass],
        %{file: "lib/policy.ex", line: 1}
      )

    assert mutations == []
  end

  test "Muex applies a decision mutation to valid compilable source" do
    source = """
    defmodule MuexSecurity.ExamplePolicy do
      def check(actor, resource), do: Policy.authorized?(actor, resource)
    end
    """

    {:ok, ast} = Language.Elixir.parse(source)

    [mutation] =
      Muex.Mutator.walk(ast, [Mutator.SecurityDecision], %{file: "lib/example_policy.ex"})

    assert {:ok, mutated_source} =
             Compiler.compile_to_source(
               mutation,
               %{ast: ast, path: "lib/example_policy.ex"},
               Language.Elixir
             )

    assert {:ok, _mutated_ast} = Code.string_to_quoted(mutated_source)
    assert mutated_source =~ "def check(actor, resource) do\n    true\n  end"
  end

  test "all operators integrate with Muex's context-aware AST traversal" do
    ast =
      quote line: 12 do
        if Policy.authorized?(actor, resource) do
          Plug.Conn.put_resp_header(conn, "x-frame-options", "DENY")
        end
      end

    mutations =
      Muex.Mutator.walk(ast, Map.values(MuexSecurity.mutators()), %{
        file: "lib/policy.ex",
        line: 1
      })

    assert Enum.any?(mutations, &(&1.mutator == Mutator.SecurityDecision))
    assert Enum.any?(mutations, &(&1.mutator == Mutator.SecurityHeader))
    assert Enum.all?(mutations, &(&1.location.line == 12))
    assert Enum.all?(mutations, &Map.has_key?(&1, :original_ast))
  end
end
