defmodule Havoc.OracleTest do
  use ExUnit.Case, async: true

  alias Havoc.Observation.{Cache, Codec, Differential, FieldPolicy, HTTPParameter, State}
  alias Havoc.Oracle

  test "no_500 detects server errors and skips observations without status" do
    assert {:error, [violation]} = Oracle.check([:no_500], %{status: 503}, "payload")
    assert violation.oracle == :no_500
    assert violation.category == :crash

    assert :ok = Oracle.check([:no_500], %{status: 422}, "payload")
    assert :ok = Oracle.check([:no_500], %{body: "no status"}, "payload")
  end

  test "no_reflection is exact and HTML-only by default" do
    payload = "<havoc-marker>"

    assert {:error, [violation]} =
             Oracle.check([:no_reflection], html_response(payload), payload)

    assert violation.oracle == :no_reflection
    assert violation.confidence == :low

    assert :ok = Oracle.check([:no_reflection], html_response("&lt;havoc-marker&gt;"), payload)

    assert :ok =
             Oracle.check(
               [:no_reflection],
               %{body: payload, content_type: "application/json"},
               payload
             )

    assert :ok = Oracle.check([:no_reflection], %{body: payload}, payload)

    assert Oracle.evaluate([:no_reflection], %{body: payload}, payload).skipped == [
             :no_reflection
           ]

    assert Oracle.evaluate([:no_reflection], %{status: 200}, payload).skipped == [:no_reflection]
  end

  test "no_injection_signal recognizes specific disclosure signatures without flagging generic SQL text" do
    assert {:error, [violation]} =
             Oracle.check(
               [:no_injection_signal],
               %{body: "ORA-00933: SQL command not properly ended"},
               "'"
             )

    assert violation.category == :injection
    assert violation.confidence == :medium

    assert :ok =
             Oracle.check(
               [:no_injection_signal],
               %{body: "Read our SQL documentation and database overview"},
               "'"
             )

    assert Oracle.evaluate([:no_injection_signal], %{status: 200}, "'").skipped == [
             :no_injection_signal
           ]
  end

  test "authorization invariants require an independent predicate" do
    oracle =
      Oracle.authz_invariant(fn observation, _payload ->
        observation.status in [401, 403] and observation.state_unchanged?
      end)

    assert :ok =
             Oracle.check([oracle], %{status: 403, state_unchanged?: true}, "payload")

    assert {:error, [violation]} =
             Oracle.check([oracle], %{status: 200, state_unchanged?: false}, "payload")

    assert violation.category == :authz_bypass

    assert_raise ArgumentError, ~r/independent predicate/, fn ->
      Oracle.normalize!([:authz_invariant])
    end
  end

  test "retains skipped checks separately from passing checks" do
    report = Oracle.evaluate([:no_500, :no_crash], %{body: "no status"}, "payload")

    assert report.passed == [:no_crash]
    assert report.skipped == [:no_500]
    assert report.violations == []
    assert :ok = Oracle.check([:no_500, :no_crash], %{body: "no status"}, "payload")
  end

  test "terminal safety rejects attacker-capable controls while permitting ordinary SGR" do
    oracle = Oracle.terminal_safety()

    assert :ok = Oracle.check([oracle], "title\n\e[31mred\e[0m", "payload")

    assert {:error, [violation]} =
             Oracle.check([oracle], "title\e]52;c;YXR0YWNrZXI=\a", "payload")

    assert violation.oracle == :terminal_safety
    assert violation.category == :terminal_control_injection
    assert "OSC" in violation.details.sequences
    assert "U+0007" in violation.details.sequences

    assert {:error, [_violation]} =
             Oracle.check([oracle], "safe\e[2Aforged\r", "payload")
  end

  test "canonical encoding rejects accepted aliases but permits rejection" do
    canonical = Oracle.canonical_encoding()

    assert :ok =
             Oracle.check([canonical], Codec.accepted("0ABC", :identity, "0ABC"), "0ABC")

    assert :ok = Oracle.check([canonical], Codec.rejected("8ABC", :noncanonical), "8ABC")

    assert {:error, [violation]} =
             Oracle.check([canonical], Codec.accepted("8ABC", :identity, "0ABC"), "8ABC")

    assert violation.category == :alternate_encoding
    assert violation.confidence == :high
  end

  test "quoted HTTP parameter integrity parses escaped values and rejects parameter smuggling" do
    input = ~S|victim", scope="admin", filler="x|
    expected = "https://#{input}.app.example.test/metadata"

    vulnerable =
      HTTPParameter.authentication(
        ~s|Bearer resource_metadata="#{expected}"|,
        "resource_metadata",
        expected,
        input: input,
        scheme: "Bearer"
      )

    escaped = expected |> String.replace("\\", "\\\\") |> String.replace("\"", "\\\"")

    fixed =
      HTTPParameter.authentication(
        ~s|Bearer resource_metadata="#{escaped}"|,
        "resource_metadata",
        expected,
        input: input,
        scheme: "Bearer"
      )

    assert {:error, [violation]} =
             Oracle.check([:quoted_parameter_integrity], vulnerable, input)

    assert violation.category == :http_parameter_injection

    assert violation.details.parsed_parameter_names == [
             "resource_metadata",
             "scope",
             "filler"
           ]

    assert :ok = Oracle.check([:quoted_parameter_integrity], fixed, input)
  end

  test "quoted HTTP parameter integrity rejects malformed output and skips unknown observations" do
    malformed =
      HTTPParameter.authentication(
        ~s|Bearer realm="unterminated|,
        "realm",
        "unterminated",
        input: "source"
      )

    assert {:error, [violation]} =
             Oracle.check([:quoted_parameter_integrity], malformed, "source")

    assert violation.details.reason == :unterminated_quoted_string

    assert Oracle.evaluate([:quoted_parameter_integrity], %{header: "Bearer realm=x"}, "source").skipped ==
             [:quoted_parameter_integrity]
  end

  test "relational observation parsers and matrices enforce finite bounds" do
    oversized =
      HTTPParameter.authentication(
        "Bearer realm=\"#{String.duplicate("a", 16_384)}\"",
        "realm",
        "value"
      )

    assert oversized.status == :incomplete
    assert oversized.reason == :header_too_large

    assert Oracle.evaluate([:quoted_parameter_integrity], oversized, "value").skipped == [
             :quoted_parameter_integrity
           ]

    too_many =
      1..129
      |> Enum.map_join(", ", &"p#{&1}=\"v\"")
      |> then(&HTTPParameter.authentication("Bearer " <> &1, "p1", "v"))

    assert too_many.status == :incomplete
    assert too_many.reason == :too_many_parameters

    fields = Enum.map(1..33, &"field-#{&1}")

    assert_raise ArgumentError, ~r/invalid field-policy observation/, fn ->
      FieldPolicy.new!(
        privileged_actor: :admin,
        restricted_actor: :reader,
        protected_fields: fields,
        paths: [%{name: :read, privileged: %{}, restricted: %{}}]
      )
    end
  end

  test "shared-cache noninterference requires a variant control and proves first-partition reuse" do
    input = %{first: "tenant-a", second: "tenant-b"}

    unsafe =
      Cache.new!(
        input: input,
        first_partition: "tenant-a",
        second_partition: "tenant-b",
        first_cache_key: "/metadata",
        second_cache_key: "/metadata",
        first_value: %{issuer: "tenant-a"},
        direct_second_value: %{issuer: "tenant-b"},
        served_second_value: %{issuer: "tenant-a"},
        second_cache_status: :hit
      )

    safe = %{unsafe | served_second_value: %{issuer: "tenant-b"}, second_cache_status: :miss}

    assert {:error, [violation]} =
             Oracle.check([:cache_partition_noninterference], unsafe, input)

    assert violation.category == :cross_tenant_cache_confusion
    assert :ok = Oracle.check([:cache_partition_noninterference], safe, input)

    nonvariant = %{unsafe | direct_second_value: unsafe.first_value}

    assert Oracle.evaluate([:cache_partition_noninterference], nonvariant, input).skipped == [
             :cache_partition_noninterference
           ]
  end

  test "actor-paired field-policy checks require privileged controls and reject alternate-path leaks" do
    input = %{field: :secret_score}

    safe =
      FieldPolicy.new!(
        input: input,
        privileged_actor: %{role: :admin},
        restricted_actor: %{role: :reader},
        protected_fields: [:secret_score],
        paths: [
          %{
            name: :record_read,
            privileged: %{secret_score: FieldPolicy.visible(20)},
            restricted: %{secret_score: FieldPolicy.hidden()}
          },
          %{
            name: :aggregate,
            privileged: %{secret_score: FieldPolicy.visible(20)},
            restricted: %{secret_score: FieldPolicy.hidden()}
          }
        ]
      )

    unsafe =
      put_in(
        safe.paths,
        [Access.at(1), Access.key(:restricted), Access.key(:secret_score)],
        FieldPolicy.visible(20)
      )
      |> then(&%{safe | paths: &1})

    assert :ok = Oracle.check([:field_policy_noninterference], safe, input)

    assert {:error, [violation]} =
             Oracle.check([:field_policy_noninterference], unsafe, input)

    assert violation.category == :field_policy_bypass
    assert [%{field: :secret_score, path: :aggregate}] = violation.details.leaks

    incomplete = put_in(safe.paths, [Access.at(0), Access.key(:privileged)], %{})
    incomplete = %{safe | paths: incomplete}

    assert Oracle.evaluate([:field_policy_noninterference], incomplete, input).skipped == [
             :field_policy_noninterference
           ]
  end

  test "differential checks require a paired observation and independent predicate" do
    oracle =
      Oracle.differential(
        :no_unauthorized_effect,
        fn control, treatment, _payload ->
          control.status == 403 and treatment.status == 403
        end,
        category: :authz_bypass,
        evidence: "an unprivileged treatment produced a privileged effect"
      )

    safe = Differential.new!(%{status: 403}, %{status: 403})
    unsafe = Differential.new!(%{status: 403}, %{status: 200})

    assert :ok = Oracle.check([oracle], safe, "actor")
    assert {:error, [violation]} = Oracle.check([oracle], unsafe, "actor")
    assert violation.evidence =~ "privileged effect"

    assert Oracle.evaluate([oracle], %{status: 200}, "actor").skipped == [
             :no_unauthorized_effect
           ]
  end

  test "bounded state growth proves observed allocation and reclamation violations" do
    oracle = Oracle.bounded_state_growth(max_delta: 2, require_reclaimed: true)

    safe = State.new!(before: 10, after: 12, settled: 10, unit: :rows)
    growth = State.new!(before: 10, after: 14, settled: 10, unit: :rows)
    leaked = State.new!(before: 10, after: 12, settled: 12, unit: :rows)

    assert :ok = Oracle.check([oracle], safe, "workload")
    assert {:error, [growth_violation]} = Oracle.check([oracle], growth, "workload")
    assert growth_violation.details.growth == 4
    assert {:error, [leak_violation]} = Oracle.check([oracle], leaked, "workload")
    assert leak_violation.details.settled_delta == 2

    missing_cleanup = State.new!(before: 10, after: 12, unit: :rows)

    assert Oracle.evaluate([oracle], missing_cleanup, "workload").skipped == [
             :bounded_state_growth
           ]
  end

  test "custom oracles compose with built-ins" do
    custom =
      Oracle.custom(:no_secret, fn observation, _payload ->
        if String.contains?(observation.body, "secret"),
          do: {:error, "response contained the test secret"},
          else: :ok
      end)

    assert {:error, violations} =
             Oracle.check(Oracle.compose([:no_500, custom]), %{status: 500, body: "secret"}, "x")

    assert Enum.map(violations, & &1.oracle) == [:no_500, :no_secret]
  end

  defp html_response(body) do
    %{body: body, content_type: "text/html; charset=utf-8"}
  end
end
