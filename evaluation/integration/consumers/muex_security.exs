Code.require_file("../assertions.exs", __DIR__)
import ExUnit.Assertions
Integration.Assertions.isolated!()
assert {:ok, config} = MuexSecurity.configure(["--mutators", "security_decision"])
assert config.mutators == [MuexSecurity.Mutator.SecurityDecision]

assert [mutation] =
         Muex.Mutator.walk(quote(do: Policy.authorized?(actor, resource)), config.mutators, %{
           file: "policy.ex",
           line: 1
         })

assert mutation.ast == true
Integration.Assertions.finish(%{checks: ["package_isolation", "muex_configuration", "mutation"]})
