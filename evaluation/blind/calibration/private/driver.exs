defmodule RampartBlindCalibration.Driver do
  @moduledoc false

  alias Core.Seed
  alias Core.Validation.Wire

  def run!([source_path, submission_path, output_path]) do
    Code.require_file(source_path)
    submission = submission_path |> File.read!() |> JSON.decode!()
    validation = Map.fetch!(submission, "validation")
    seed_value = Map.fetch!(validation, "seed")

    seed = %Seed{
      id: seed_id(validation, seed_value),
      value: seed_value,
      classes: [:blind_evaluation, :authorization],
      provenance: :external,
      meta: %{"challenge_id" => Map.fetch!(submission, "challenge_id")}
    }

    result =
      Havoc.validate(seed, &execute/1,
        oracles: [authorization_oracle()],
        persist: false,
        property_id: Map.fetch!(validation, "contract_id"),
        property_name: "blind equivalent-route authorization"
      )

    File.write!(output_path, JSON.encode!(Wire.result(result)))
  end

  def run!(_arguments) do
    raise ArgumentError, "driver expects SOURCE SUBMISSION OUTPUT"
  end

  defp execute(request) do
    privileged =
      BlindCalibration.RoutePolicy.handle(%{
        "actor" => "admin",
        "path" => "/.well-known/admin/change-email"
      })

    canonical =
      BlindCalibration.RoutePolicy.handle(%{
        "actor" => "anonymous",
        "path" => "/admin/change-email"
      })

    unless privileged == %{status: 200, effect: :email_changed} and
             canonical.status in [401, 403] and canonical.effect == :none do
      raise "independent route liveness or canonical-policy control failed"
    end

    %{candidate: BlindCalibration.RoutePolicy.handle(request), request: request}
  end

  defp authorization_oracle do
    Havoc.Oracle.authz_invariant(
      fn observation, payload ->
        candidate = observation.candidate
        protected? = payload["path"] in ["/admin/change-email", "/.well-known/admin/change-email"]
        restricted? = payload["actor"] != "admin"

        if protected? and restricted? do
          candidate.status in [401, 403] and candidate.effect == :none
        else
          true
        end
      end,
      evidence: "restricted actor reached an equivalent state-changing route"
    )
  end

  defp seed_id(validation, seed_value) do
    Core.Finding.dedupe_id(:blind_evaluation, [
      Map.fetch!(validation, "contract_id"),
      Map.fetch!(validation, "replay_nonce"),
      Havoc.TermCodec.fingerprint(seed_value)
    ])
  end
end

RampartBlindCalibration.Driver.run!(System.argv())
