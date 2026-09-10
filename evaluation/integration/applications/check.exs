Code.require_file("assertions.exs", System.fetch_env!("RAMPART_GATE_SUPPORT"))

defmodule Integration.Applications do
  import ExUnit.Assertions
  alias Fixture.Server

  def run do
    assert Application.spec(:plug, :vsn) == ~c"1.20.3"
    assert Application.spec(:bandit, :vsn) == ~c"1.12.5"
    File.mkdir_p!("proofs")
    results = [cache(), routes()]
    inventory = RampartSAST.Isolated.inventory(".")
    assert inventory.status == :complete
    assert Enum.any?(inventory.inventory["facts"], &(&1["kind"] == "call"))
    hashes = Map.new(Path.wildcard("lib/*.ex") ++ ["mix.lock"], &{&1, hash(File.read!(&1))})

    Integration.Assertions.finish(%{
      fixtures: results,
      plug: "1.20.3",
      bandit: "1.12.5",
      source_hashes: hashes,
      inventory_id: inventory.inventory["id"],
      historical_cve_reproduction: false
    })
  end

  defp cache do
    seed = %Core.Seed{
      id: "cache-scenario",
      value: %{"first" => "alpha", "second" => "beta"},
      provenance: :generated
    }

    run_pair(
      "tenant_cache",
      Fixture.TenantCache,
      seed,
      [&Havoc.Oracle.cache_partition_noninterference/0],
      &cache_target/1,
      fn server ->
        assert %{status: 401} = Server.request(server, :get, "/profile")

        assert %{body: "alpha-private-profile"} =
                 Server.request(server, :get, "/uncached/profile", token("alpha"))

        assert %{body: "beta-private-profile"} =
                 Server.request(server, :get, "/uncached/profile", token("beta"))
      end
    )
  end

  defp cache_target(server) do
    fn payload ->
      Agent.update(server.store, &%{&1 | cache: %{}})
      first_tenant = payload["first"]
      second_tenant = payload["second"]
      first = Server.request(server, :get, "/uncached/profile", token(first_tenant))
      second = Server.request(server, :get, "/uncached/profile", token(second_tenant))
      fill = Server.request(server, :get, "/profile", token(first_tenant))
      served = Server.request(server, :get, "/profile", token(second_tenant))

      unless Enum.all?([first, second, fill, served], &(&1.status == 200)),
        do: raise("cache controls unavailable")

      Havoc.Observation.Cache.new!(
        input: payload,
        first_partition: first_tenant,
        second_partition: second_tenant,
        first_cache_key: fill.headers["x-cache-key"],
        second_cache_key: served.headers["x-cache-key"],
        first_value: first.body,
        direct_second_value: second.body,
        served_second_value: served.body,
        second_cache_status: if(served.headers["x-cache"] == "hit", do: :hit, else: :miss)
      )
    end
  end

  defp routes do
    seed = %Core.Seed{
      id: "alternate-route",
      value: %{"path" => "/legacy/rotate"},
      provenance: :generated
    }

    oracle = fn ->
      Havoc.Oracle.authz_invariant(
        fn observation, _payload ->
          observation.status in [403, 404] and observation.before == observation.after
        end,
        evidence:
          "an anonymous request changed protected application state through an alternate mount"
      )
    end

    run_pair("route_gateway", Fixture.RouteGateway, seed, [oracle], &route_target/1, fn server ->
      for path <- ["/api/rotate", "/legacy/rotate"] do
        before = Agent.get(server.store, & &1.rotations)

        assert %{status: 201} =
                 Server.request(server, :post, path, [
                   {"authorization", "Bearer admin-fixture-token"}
                 ])

        assert Agent.get(server.store, & &1.rotations) == before + 1
      end

      assert %{status: 403} = Server.request(server, :post, "/api/rotate")
      before = Agent.get(server.store, & &1.rotations)
      assert %{status: status} = Server.request(server, :post, "/missing/rotate")
      assert status in [403, 404]
      assert Agent.get(server.store, & &1.rotations) == before
    end)
  end

  defp route_target(server) do
    fn payload ->
      before = Agent.get(server.store, & &1.rotations)
      response = Server.request(server, :post, payload["path"])
      if response.status >= 500, do: raise("route fixture failed")
      %{status: response.status, before: before, after: Agent.get(server.store, & &1.rotations)}
    end
  end

  defp run_pair(name, module, seed, oracle_builders, target_builder, controls) do
    corpus = "proofs/#{name}-corpus.json"

    options = [
      oracles: Enum.map(oracle_builders, & &1.()),
      corpus_path: corpus,
      property_id: name,
      property_name: name
    ]

    vulnerable = Server.start(module, :vulnerable)
    fixed = Server.start(module, :fixed)

    try do
      controls.(vulnerable)
      controls.(fixed)

      assert %{verdict: :confirmed, findings: [_ | _]} =
               confirmed = Havoc.validate(seed, target_builder.(vulnerable), options)

      assert [saved] = Havoc.Corpus.load(path: corpus)
      assert saved.value == seed.value

      assert %{verdict: :confirmed} =
               replayed = Havoc.validate(saved, target_builder.(vulnerable), options)

      assert %{verdict: :refuted, findings: []} =
               refuted = Havoc.validate(saved, target_builder.(fixed), options)

      Server.stop(vulnerable)

      assert %{verdict: :inconclusive, findings: []} =
               failure = Havoc.validate(saved, target_builder.(vulnerable), options)

      for {label, result} <- [
            {"confirmed", confirmed},
            {"replay", replayed},
            {"fixed", refuted},
            {"failure", failure}
          ] do
        File.write!(
          "proofs/#{name}-#{label}.json",
          result |> Core.Validation.Wire.result() |> Core.Validation.Wire.encode!()
        )
      end

      %{
        name: name,
        vulnerable: "confirmed",
        fixed: "refuted",
        replay: "confirmed",
        unavailable_application: "inconclusive",
        seed_id: saved.id,
        proof_hashes:
          Map.new(
            Path.wildcard("proofs/#{name}*.json"),
            &{Path.basename(&1), hash(File.read!(&1))}
          )
      }
    after
      if Process.alive?(vulnerable.supervisor), do: Server.stop(vulnerable)
      Server.stop(fixed)
      refute Process.alive?(fixed.supervisor)
      refute Process.alive?(vulnerable.store)
    end
  end

  defp token(tenant), do: [{"authorization", "Bearer #{tenant}-fixture-token"}]
  defp hash(binary), do: :crypto.hash(:sha256, binary) |> Base.encode16(case: :lower)
end

Integration.Applications.run()
