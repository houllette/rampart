defmodule Core.SeedTest do
  use ExUnit.Case, async: true

  alias Core.Seed

  test "carries a promoted value and its cross-tool origin without interpreting it" do
    seed = %Seed{
      id: "seed-1",
      value: "https://192.0.2.10/",
      classes: [:target, :discovery],
      provenance: :promoted_finding,
      origin: {:portico, "portico:finding-id"},
      meta: %{scheme: "https"}
    }

    assert seed.origin == {:portico, "portico:finding-id"}
    assert seed.classes == [:target, :discovery]
    assert seed.meta.scheme == "https"
  end
end
