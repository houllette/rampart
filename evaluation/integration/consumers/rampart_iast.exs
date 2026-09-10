Code.require_file("../assertions.exs", __DIR__)
import ExUnit.Assertions
Integration.Assertions.isolated!()

assert [%{id: "iast.exact-marker-reaches-sink.v1", side_effects: :test_execution}] =
         RampartIAST.validation_actions()

Integration.Assertions.finish(%{
  checks: ["package_isolation", "research_action_contract"],
  agent_enabled: false
})
