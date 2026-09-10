Code.require_file("../assertions.exs", __DIR__)
import ExUnit.Assertions
Integration.Assertions.isolated!()
assert [%{id: "portico.endpoint-reachable.v1"}] = Portico.validation_actions()
assert %{value: "127.0.0.1"} = Portico.Target.parse!("127.0.0.1")

assert_raise Core.Scope.Error, fn ->
  Core.Scope.ensure_all_authorized!([Portico.Target.parse!("127.0.0.1")], Core.Scope.DenyAll)
end

Integration.Assertions.finish(%{
  checks: ["package_isolation", "action", "target", "scope_denial"]
})
