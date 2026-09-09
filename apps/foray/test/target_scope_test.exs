defmodule Foray.TargetScopeTest do
  use ExUnit.Case, async: true

  alias Foray.Scope.Allowlist
  alias Foray.Target

  test "normalizes absolute HTTP targets and rejects unsafe URL forms" do
    assert %Target{
             url: "https://app.example/api?q=1",
             scheme: :https,
             host: "app.example",
             port: 443,
             path: "/api"
           } = Target.parse!("HTTPS://App.Example/api?q=1")

    assert {:error, :unsupported_scheme} = Target.parse("ftp://app.example/file")
    assert {:error, :userinfo_forbidden} = Target.parse("https://user:pass@app.example/")
    assert {:error, :fragment_forbidden} = Target.parse("https://app.example/#fragment")
  end

  test "authorizes exact origins, segment-bounded paths, and explicit wildcard subdomains" do
    policy = Allowlist.new!(["https://app.example/api", "https://*.example.net/"])

    assert Core.Scope.authorized?(Target.parse!("https://app.example/api"), policy)
    assert Core.Scope.authorized?(Target.parse!("https://app.example/api/v1/users"), policy)
    refute Core.Scope.authorized?(Target.parse!("https://app.example/apix"), policy)
    refute Core.Scope.authorized?(Target.parse!("http://app.example/api"), policy)
    refute Core.Scope.authorized?(Target.parse!("https://app.example:8443/api"), policy)
    assert Core.Scope.authorized?(Target.parse!("https://edge.example.net/"), policy)
    refute Core.Scope.authorized?(Target.parse!("https://example.net/"), policy)
  end

  test "canonicalizes encoded traversal before applying a path rule" do
    policy = Allowlist.new!(["https://app.example/api/"])

    refute Core.Scope.authorized?(Target.parse!("https://app.example/api/%2e%2e/admin"), policy)
  end

  test "accepts Core target seeds and rejects payload seeds as targets" do
    target_seed = %Core.Seed{
      id: "portico:https",
      value: "https://app.example",
      classes: [:target]
    }

    assert [%Target{host: "app.example"}] = Foray.target(target_seed).targets

    payload_seed = %Core.Seed{id: "havoc:payload", value: "admin", classes: [:discovery]}

    assert_raise ArgumentError, ~r/target seeds require the :target class/, fn ->
      Foray.target(payload_seed)
    end
  end
end
