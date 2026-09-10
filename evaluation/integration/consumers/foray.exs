Code.require_file("../assertions.exs", __DIR__)
import ExUnit.Assertions
Integration.Assertions.isolated!()

scan =
  Foray.target("http://127.0.0.1")
  |> Foray.fuzz_path(wordlist: [%Core.Seed{id: "one", value: "admin", provenance: :wordlist}])

assert [job] = Foray.JobBuilder.build(scan)
assert job.target.url == "http://127.0.0.1/FUZZ"
assert [%{id: "foray.http-match-reproduces.v1"}] = Foray.validation_actions()
Integration.Assertions.finish(%{checks: ["package_isolation", "whole_job", "action"]})
