defmodule HavocTest do
  use ExUnit.Case, async: true

  test "promotes sister-tool findings without depending on the sister library" do
    finding = %Core.Finding{id: "foray:finding", source: :foray}
    seed = Havoc.promote(finding, "' OR '1'='1", classes: [:sqli])

    assert seed.provenance == :promoted_finding
    assert seed.origin == {:foray, "foray:finding"}
    assert seed.classes == [:sqli]
    assert seed.value == "' OR '1'='1"
  end
end
