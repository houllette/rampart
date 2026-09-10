Code.require_file("../assertions.exs", __DIR__)
import ExUnit.Assertions
Integration.Assertions.isolated!()
assert {"consumer", 0} = Core.Runner.run(["printf", "consumer"])
assert Core.Scope.authorized?("anything", Core.Scope.DenyAll) == false
Integration.Assertions.finish(%{checks: ["package_isolation", "native_runner", "deny_scope"]})
