defmodule RampartEvaluation.Corpus do
  @moduledoc false

  @target_sources [
    "evaluation/fixtures/composed/handler.ex",
    "evaluation/fixtures/composed/target.ex"
  ]
  @dependency_sources ["evaluation/fixtures/composed/dependency.ex"]
  @budgets %{
    max_scan_ms: 5_000,
    max_isolated_scan_ms: 10_000,
    max_query_p95_us: 100_000,
    max_artifact_bytes: 1_000_000,
    max_model_evidence_bytes: 64_000,
    max_graph_nodes: 32,
    max_targeted_trace_ms: 250,
    max_cross_process_probe_ms: 10_000
  }

  @spec cases() :: [map()]
  def cases do
    [
      case_spec(
        "composed.command-boundary-exact-marker.v1",
        :command,
        :command_patched,
        "evaluation.command.v1",
        "evaluation.command-boundary-candidate.v1",
        :command_execution_boundary,
        "System.cmd/2",
        "external_process",
        %{sink_candidate_count: 6}
      ),
      case_spec(
        "composed.ambiguous-command-sites-exact-marker.v1",
        :ambiguous_command,
        :ambiguous_command_patched,
        "evaluation.command.v1",
        "evaluation.ambiguous-command-sites-candidate.v1",
        :command_execution_boundary,
        "System.cmd/2",
        "external_process",
        %{
          dependency_function: "RampartEvaluation.Fixture.Dependency.command_ambiguous/2",
          localization: :ambiguous,
          selected_sink_candidate_count: 2,
          sink_candidate_count: 6
        }
      ),
      case_spec(
        "composed.deserialization-boundary-exact-marker.v1",
        :deserialize,
        :deserialize_patched,
        "evaluation.deserialize.v1",
        "evaluation.deserialization-boundary-candidate.v1",
        :unsafe_deserialization_boundary,
        "erlang.binary_to_term/2",
        "deserialization",
        %{}
      ),
      case_spec(
        "composed.file-write-boundary-exact-marker.v1",
        :file_write,
        :file_write_patched,
        "evaluation.file-write.v1",
        "evaluation.file-write-boundary-candidate.v1",
        :filesystem_write_content_boundary,
        "File.write!/2",
        "filesystem_access",
        %{}
      ),
      plug_case(),
      trace_overhead_case(),
      cross_process_feasibility_case(),
      otp_case(),
      historical_plug_static_case(),
      historical_terminal_contract_case(),
      historical_ulid_contract_case(),
      historical_http_parameter_contract_case(),
      historical_cache_tenancy_contract_case(),
      historical_ash_field_policy_contract_case()
    ]
  end

  defp case_spec(
         id,
         function,
         patched_function,
         sink_id,
         candidate_id,
         category,
         sink_function,
         behavior,
         overrides
       ) do
    module = "RampartEvaluation.Fixture"
    function_name = Atom.to_string(function)
    patched_name = Atom.to_string(patched_function)

    %{
      id: id,
      kind: :exact_marker,
      tier: :composed_application,
      target_sources: @target_sources,
      dependency_sources: @dependency_sources,
      expected:
        Map.merge(
          %{
            callback: "#{module}.Handler.#{function_name}/1",
            implementation: "#{module}.Target.#{function_name}/1",
            dependency_package: "rampart_evaluation_dependency",
            source_function: "#{module}.Target.#{function_name}/1",
            patched_function: "#{module}.Target.#{patched_name}/1",
            dependency_function: "#{module}.Dependency.#{function_name}/1",
            sink_function: sink_function,
            sink_behavior: behavior,
            runtime_module: RampartEvaluation.Fixture.Target,
            runtime_function: function,
            runtime_patched_function: patched_function,
            sink_id: sink_id,
            candidate_id: candidate_id,
            sink_category: category,
            localization: :unique_static_call_site,
            sink_candidate_count: 2,
            selected_sink_candidate_count: 1
          },
          overrides
        ),
      budgets: @budgets
    }
  end

  defp plug_case do
    %{
      id: "package.plug-response-boundary-exact-marker.v1",
      kind: :exact_marker,
      tier: :package_provider,
      target_sources: ["evaluation/fixtures/plug/target.ex"],
      dependency_sources: [],
      scan_options: [
        module_owners: %{"Plug" => "plug"},
        behavior_classifiers: [RampartSAST.Behavior.BEAM, RampartSAST.Behavior.Plug]
      ],
      expected: %{
        callback: "RampartEvaluation.Plug.Handler.send_body/1",
        implementation: "RampartEvaluation.Plug.Target.send_body/1",
        dependency_package: "plug",
        source_function: "RampartEvaluation.Plug.Target.send_body/1",
        patched_function: "RampartEvaluation.Plug.Target.send_body_patched/1",
        dependency_function: "RampartEvaluation.Plug.Target.send_body/1",
        sink_function: "Plug.Conn.send_resp/3",
        sink_behavior: "http_response_write",
        runtime_module: RampartEvaluation.Plug.Target,
        runtime_function: :send_body,
        runtime_patched_function: :send_body_patched,
        sink_id: "evaluation.plug-send-resp.v1",
        candidate_id: "evaluation.plug-response-boundary-candidate.v1",
        sink_category: :http_response_body_boundary,
        localization: :unique_static_call_site,
        sink_candidate_count: 2,
        selected_sink_candidate_count: 1
      },
      budgets: @budgets
    }
  end

  defp trace_overhead_case do
    %{
      id: "iast.targeted-trace-overhead.v1",
      kind: :trace_overhead,
      tier: :runtime_measurement,
      target_sources: ["evaluation/fixtures/overhead/target.ex"],
      dependency_sources: [],
      expected: %{
        source_function: "RampartEvaluation.Overhead.Target.run/1",
        sink_function: "RampartEvaluation.Overhead.Sink.observe/1",
        sink_id: "evaluation.overhead-observer.v1",
        candidate_id: "evaluation.targeted-trace-overhead-candidate.v1",
        sample_count: 7
      },
      budgets: @budgets
    }
  end

  defp cross_process_feasibility_case do
    %{
      id: "iast.cross-process-boundary-feasibility.v3",
      kind: :cross_process_feasibility,
      tier: :runtime_measurement,
      target_sources: [],
      dependency_sources: [],
      expected: %{
        direct_flow_count: 8,
        sender_count: 4,
        direct_value_only_candidate_pair_count: 64,
        otp_flow_count: 4,
        boundary_value_only_candidate_pair_count: 16,
        ets_event_count: 16,
        adversarial_flow_count: 4,
        task_failure_flow_count: 2,
        trace_loss_observed_event_count: 3,
        external_state_joined_edge_count: 1,
        stress_flow_count: 64,
        stress_sender_count: 16,
        stress_noise_count: 512,
        stress_value_only_candidate_pair_count: 4_096,
        distributed_flow_count: 4,
        unresolved_boundaries: [
          :process_dictionary_targeted_read,
          :distributed_handoff_without_explicit_envelope
        ]
      },
      budgets: @budgets
    }
  end

  defp historical_plug_static_case do
    root = "evaluation/fixtures/historical/plug_static_null_byte"

    %{
      id: "historical.plug-static-null-byte.cve-2017-1000052.v1",
      kind: :historical_regression,
      tier: :historical,
      target_sources: [
        "#{root}/vulnerable.ex",
        "#{root}/fixed.ex",
        "#{root}/upstream_vulnerable_static.ex",
        "#{root}/upstream_fixed_static.ex"
      ],
      dependency_sources: [],
      expected: %{
        vulnerable_function: "RampartEvaluation.Historical.PlugStaticVulnerable.invalid_path?/1",
        fixed_function: "RampartEvaluation.Historical.PlugStaticFixed.invalid_path?/1",
        candidate_function: "String.contains?/2",
        vulnerable_module: RampartEvaluation.Historical.PlugStaticVulnerable,
        fixed_module: RampartEvaluation.Historical.PlugStaticFixed,
        input: "sample.txt\0.html",
        upstream_function: "Plug.Static.invalid_path?/1",
        upstream_vulnerable_path: "#{root}/upstream_vulnerable_static.ex",
        upstream_fixed_path: "#{root}/upstream_fixed_static.ex",
        upstream_vulnerable_sha256:
          "5304dbb7023ec6bcf20b0cc107659e450805c94224725639e7af436ca8118525",
        upstream_fixed_sha256: "502fd12441ed2787c0bb93819cc62db6865781f7f5a690adf5880771dfeeac50"
      },
      provenance: %{
        project: "elixir-plug/plug",
        advisory: "GHSA-2q6v-32mr-8p8x",
        cve: "CVE-2017-1000052",
        vulnerable_revision: "c30ffae4d221db68babb3c1513b094a7b0d413f2",
        fixed_revision: "cc583068e482e22bab33931fb4d5d36e7d889fa6",
        source_path: "lib/plug/static.ex",
        license: "Apache-2.0",
        fixture_kind: :adapted_excerpt
      },
      budgets: @budgets
    }
  end

  defp historical_terminal_contract_case do
    root = "evaluation/fixtures/historical/terminal_control"

    %{
      id: "historical.terminal-control-contract.cve-2026-82710.v1",
      kind: :historical_contract_regression,
      tier: :historical,
      target_sources: ["#{root}/fixture.ex"],
      dependency_sources: [],
      expected: %{
        vulnerable_function: "RampartEvaluation.Historical.TerminalControl.vulnerable/1",
        fixed_function: "RampartEvaluation.Historical.TerminalControl.fixed/1",
        runtime_module: RampartEvaluation.Historical.TerminalControl,
        runtime_vulnerable_function: :vulnerable,
        runtime_fixed_function: :fixed,
        input: "ordinary\e]52;c;YXR0YWNrZXI=\a\e[2Aforged\r",
        oracle: :terminal_safety,
        observation_shape: :terminal_output,
        finding_category: :terminal_control_injection,
        static_kind: :binding,
        static_object: "rendered",
        static_expression_kind: :interpolation,
        static_source_variable: "metadata",
        static_subjects: [
          "RampartEvaluation.Historical.TerminalControl.vulnerable/1",
          "RampartEvaluation.Historical.TerminalControl.fixed/1"
        ]
      },
      provenance: %{
        project: "ash-project/usage_rules",
        advisory: "CVE-2026-82710",
        vulnerable_revision: "f1c829689a794307af77925a306846b5b3e14756",
        fixed_revision: "3b8ebb4117d3272bbd436e6c2432113ba6685dbb",
        source_path: "lib/mix/tasks/usage_rules.search_docs.ex",
        license: "MIT",
        fixture_kind: :adapted_predicate,
        related_advisory: "CVE-2026-82584"
      },
      budgets: @budgets
    }
  end

  defp historical_ulid_contract_case do
    root = "evaluation/fixtures/historical/ulid_canonical"

    %{
      id: "historical.canonical-codec-contract.cve-2026-81638.v1",
      kind: :historical_contract_regression,
      tier: :historical,
      target_sources: ["#{root}/fixture.ex"],
      dependency_sources: [],
      expected: %{
        vulnerable_function: "RampartEvaluation.Historical.ULIDCanonical.vulnerable/1",
        fixed_function: "RampartEvaluation.Historical.ULIDCanonical.fixed/1",
        runtime_module: RampartEvaluation.Historical.ULIDCanonical,
        runtime_vulnerable_function: :vulnerable,
        runtime_fixed_function: :fixed,
        input: "8" <> String.duplicate("0", 25),
        oracle: :canonical_encoding,
        observation_shape: :direct,
        finding_category: :alternate_encoding,
        static_kind: :call,
        static_object: "Havoc.Observation.Codec.accepted/4",
        static_argument_position: 1,
        static_expression_kind: :variable,
        static_source_variable: "input",
        static_subjects: [
          "RampartEvaluation.Historical.ULIDCanonical.vulnerable/1",
          "RampartEvaluation.Historical.ULIDCanonical.fixed/1"
        ]
      },
      provenance: %{
        project: "ash-project/ash_double_entry",
        advisory: "CVE-2026-81638",
        vulnerable_revision: "7fb25b80ec39472a18322537702b85e1b4a88c65",
        fixed_revision: "d3e688d300a581ae214b3ca7d95ef4de63fbb050",
        source_path: "lib/ulid.ex",
        license: "MIT",
        fixture_kind: :adapted_predicate
      },
      budgets: @budgets
    }
  end

  defp historical_http_parameter_contract_case do
    root = "evaluation/fixtures/historical/http_quoted_parameter"

    %{
      id: "historical.http-quoted-parameter-contract.cve-2026-82756.v1",
      kind: :historical_contract_regression,
      tier: :historical,
      target_sources: ["#{root}/fixture.ex"],
      dependency_sources: [],
      scan_options: [
        module_owners: %{"Plug" => "plug"},
        behavior_classifiers: [RampartSAST.Behavior.Plug]
      ],
      expected: %{
        vulnerable_function: "RampartEvaluation.Historical.HTTPQuotedParameter.vulnerable/1",
        fixed_function: "RampartEvaluation.Historical.HTTPQuotedParameter.fixed/1",
        runtime_module: RampartEvaluation.Historical.HTTPQuotedParameter,
        runtime_vulnerable_function: :vulnerable,
        runtime_fixed_function: :fixed,
        input: ~s|victim", scope="admin", filler="x|,
        oracle: :quoted_parameter_integrity,
        observation_shape: :direct,
        finding_category: :http_parameter_injection,
        static_kind: :call,
        static_object: "Plug.Conn.put_resp_header/3",
        static_argument_position: 3,
        static_expression_kind: :variable,
        static_source_variable: "challenge",
        static_behavior: "http_response_header_write",
        static_subjects: [
          "RampartEvaluation.Historical.HTTPQuotedParameter.vulnerable/1",
          "RampartEvaluation.Historical.HTTPQuotedParameter.fixed/1"
        ],
        static_controls: [
          %{
            kind: :binding,
            object: "challenge",
            subject: "RampartEvaluation.Historical.HTTPQuotedParameter.vulnerable/1",
            expression_kind: :interpolation,
            source_variables: ["metadata_url"]
          },
          %{
            kind: :binding,
            object: "challenge",
            subject: "RampartEvaluation.Historical.HTTPQuotedParameter.fixed/1",
            expression_kind: :interpolation,
            source_variables: ["escaped"]
          }
        ]
      },
      provenance: %{
        project: "ash-project/ash_authentication_oauth2_server",
        advisory: "CVE-2026-82756",
        vulnerable_revision: "268b591261a3473ab9b87272963e4dd2fd99d972",
        fixed_revision: "09f97476715da031b136eaec7b2cda2363ad8149",
        source_path: "lib/ash_authentication_phoenix/oauth2_server/bearer_plug.ex",
        license: "MIT",
        fixture_kind: :adapted_predicate
      },
      budgets: @budgets
    }
  end

  defp historical_cache_tenancy_contract_case do
    root = "evaluation/fixtures/historical/cache_tenancy"

    %{
      id: "historical.cache-tenancy-contract.cve-2026-82755.v1",
      kind: :historical_contract_regression,
      tier: :historical,
      target_sources: ["#{root}/fixture.ex"],
      dependency_sources: [],
      scan_options: [
        module_owners: %{"Plug" => "plug"},
        behavior_classifiers: [RampartSAST.Behavior.Plug]
      ],
      expected: %{
        vulnerable_function: "RampartEvaluation.Historical.CacheTenancy.vulnerable/1",
        fixed_function: "RampartEvaluation.Historical.CacheTenancy.fixed/1",
        runtime_module: RampartEvaluation.Historical.CacheTenancy,
        runtime_vulnerable_function: :vulnerable,
        runtime_fixed_function: :fixed,
        input: %{
          first_tenant: "tenant-a",
          second_tenant: "tenant-b",
          path: "/.well-known/oauth-authorization-server"
        },
        oracle: :cache_partition_noninterference,
        observation_shape: :direct,
        finding_category: :cross_tenant_cache_confusion,
        static_kind: :binding,
        static_object: "observation",
        static_expression_kind: :call,
        static_source_variable: "input",
        static_subjects: [
          "RampartEvaluation.Historical.CacheTenancy.vulnerable/1",
          "RampartEvaluation.Historical.CacheTenancy.fixed/1"
        ],
        static_controls: [
          %{
            kind: :call_argument,
            object: "RampartEvaluation.Historical.CacheTenancy.observe/2#argument/2",
            subject: "RampartEvaluation.Historical.CacheTenancy.vulnerable/1",
            expression_kind: :literal,
            preview: ":public"
          },
          %{
            kind: :call_argument,
            object: "RampartEvaluation.Historical.CacheTenancy.observe/2#argument/2",
            subject: "RampartEvaluation.Historical.CacheTenancy.fixed/1",
            expression_kind: :literal,
            preview: ":private"
          }
        ]
      },
      provenance: %{
        project: "ash-project/ash_authentication_oauth2_server",
        advisory: "CVE-2026-82755",
        vulnerable_revision: "09f97476715da031b136eaec7b2cda2363ad8149",
        fixed_revision: "768d87f70e4e97ae1d2bf1606b5bf3f4d03f24a1",
        source_path: "lib/ash_authentication_phoenix/oauth2_server/protocol_router.ex",
        license: "MIT",
        fixture_kind: :adapted_predicate
      },
      budgets: @budgets
    }
  end

  defp historical_ash_field_policy_contract_case do
    root = "evaluation/fixtures/historical/ash_field_policy"

    %{
      id: "historical.ash-field-policy-contract.cve-2026-78216.v1",
      kind: :historical_contract_regression,
      tier: :historical,
      target_sources: ["#{root}/fixture.ex", "#{root}/static.ex"],
      dependency_sources: [],
      scan_options: [
        module_owners: %{"Ash" => "ash"},
        behavior_classifiers: [RampartSAST.Behavior.Ash]
      ],
      expected: %{
        vulnerable_function: "RampartEvaluation.Historical.AshFieldPolicy.vulnerable/1",
        fixed_function: "RampartEvaluation.Historical.AshFieldPolicy.fixed/1",
        runtime_module: RampartEvaluation.Historical.AshFieldPolicy,
        runtime_vulnerable_function: :vulnerable,
        runtime_fixed_function: :fixed,
        input: %{field: :secret_score, value: 20},
        oracle: :field_policy_noninterference,
        observation_shape: :direct,
        finding_category: :field_policy_bypass,
        static_kind: :call,
        static_object: "Ash.aggregate/3",
        static_argument_position: 2,
        static_expression_kind: :tuple,
        static_source_variable: "field",
        static_behavior: "field_aggregate_read",
        static_subjects: [
          "RampartEvaluation.Historical.AshFieldPolicy.Static.vulnerable/2",
          "RampartEvaluation.Historical.AshFieldPolicy.Static.fixed/2"
        ],
        static_controls: [
          %{
            kind: :binding,
            object: "options",
            subject: "RampartEvaluation.Historical.AshFieldPolicy.Static.vulnerable/2",
            expression_kind: :keyword,
            preview: "[]"
          },
          %{
            kind: :binding,
            object: "options",
            subject: "RampartEvaluation.Historical.AshFieldPolicy.Static.fixed/2",
            expression_kind: :keyword,
            preview_contains: "authorize_fields?: true"
          }
        ]
      },
      provenance: %{
        project: "ash-project/ash_lua",
        advisory: "CVE-2026-78216",
        vulnerable_revision: "da14a4af0671be66a68de47eb0c831f5063b1b18",
        fixed_revision: "266a5dcc56d5015b6d316c10606169e753b07450",
        source_path: "lib/ash_lua/runtime.ex",
        license: "MIT",
        fixture_kind: :adapted_predicate,
        related_advisories: ["CVE-2026-78230", "CVE-2026-82586"]
      },
      budgets: @budgets
    }
  end

  defp otp_case do
    %{
      id: "otp.gen-server-cross-process-boundary.v1",
      kind: :unsupported_process_scope,
      tier: :otp_boundary,
      target_sources: ["evaluation/fixtures/otp/target.ex"],
      dependency_sources: ["evaluation/fixtures/otp/server.ex"],
      expected: %{
        dependency_package: "rampart_evaluation_otp",
        source_function: "RampartEvaluation.OTP.Target.run/1",
        request_function: "RampartEvaluation.OTP.Server.consume/2",
        sink_function: "System.cmd/2",
        sink_id: "evaluation.command.v1",
        candidate_id: "evaluation.otp-cross-process-candidate.v1"
      },
      budgets: @budgets
    }
  end
end
