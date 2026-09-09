defmodule Portico.Validator do
  @moduledoc """
  Deterministically rechecks one Portico endpoint observation.

  Validation bypasses broad discovery and runs the configured enrichment engine
  against exactly the observed IP, protocol, and port. The target is scope
  checked and audited before the engine launches, just like a normal pipeline.
  """

  @behaviour Core.Validator

  alias Core.Validation
  alias Core.Validation.{Action, Evidence, Request}
  alias Portico.Discovery.Result, as: DiscoveryResult
  alias Portico.Enrichment.Stage
  alias Portico.{Finding, Host, Port, Target}

  @action_id "portico.endpoint-reachable.v1"

  @impl true
  def actions, do: [action()]

  @doc false
  @spec action() :: Action.t()
  def action do
    %Action{
      id: @action_id,
      tool: :portico,
      name: :endpoint_reachable,
      description: "recheck one observed IP, protocol, and port with an enrichment engine",
      accepts: [:finding],
      side_effects: :authorized_probe,
      meta: %{requires_scope: true, observation: :point_in_time}
    }
  end

  @impl true
  def validate(%Request{subject: %Core.Finding{} = candidate} = request, opts) do
    details = endpoint!(candidate)
    replay_seed = replay_seed(candidate, details)
    scan = validation_scan(details, opts)

    entry = %DiscoveryResult{
      target: details.target,
      ip: details.ip,
      protocol: details.protocol,
      ports: [details.port],
      meta: %{validation_id: request.id}
    }

    case Stage.run([entry], scan) do
      {:ok, [%Host{} = host]} -> verdict(request, candidate, replay_seed, details, host)
      {:ok, hosts} -> inconclusive(request, replay_seed, {:invalid_host_results, hosts})
    end
  end

  defp validation_scan(details, opts) do
    schema = [
      scope: [type: :any],
      audit: [type: :any, default: nil],
      metadata: [type: :map, default: %{}],
      engine: [type: :atom, default: :nmap],
      engine_options: [type: :keyword_list, default: []]
    ]

    opts = NimbleOptions.validate!(opts, schema)
    scope = opts[:scope] || Application.get_env(:portico, :scope, Core.Scope.DenyAll)

    scan =
      Portico.scan(details.ip,
        scope: scope,
        audit: opts[:audit],
        metadata: Map.put(opts[:metadata], :validation, true)
      )

    Portico.enrich(scan, [engine: opts[:engine]] ++ opts[:engine_options])
  end

  defp verdict(request, candidate, replay_seed, details, %Host{} = host) do
    cond do
      host.status in [:error, :timeout] ->
        inconclusive(request, replay_seed, {:host_status, host.status, host.meta})

      open_port?(host, details) ->
        finding =
          host
          |> Finding.from_host()
          |> Enum.find(&same_endpoint?(&1, details))
          |> attach_validation_seed!(replay_seed, candidate)

        Validation.confirmed(
          request,
          [finding],
          replay_seed,
          %Evidence{
            summary: "#{details.port}/#{details.protocol} was open when rechecked",
            facts: %{
              ip: details.ip,
              port: details.port,
              protocol: details.protocol,
              state: "open"
            },
            raw: host
          }
        )

      true ->
        Validation.refuted(
          request,
          replay_seed,
          %Evidence{
            summary: "#{details.port}/#{details.protocol} was not open when rechecked",
            facts: %{
              ip: details.ip,
              port: details.port,
              protocol: details.protocol,
              host_status: host.status
            },
            raw: host
          }
        )
    end
  end

  defp attach_validation_seed!(nil, _seed, _candidate) do
    raise ArgumentError, "enrichment reported an open port without a matching Portico finding"
  end

  defp attach_validation_seed!(finding, seed, candidate) do
    %{
      finding
      | seed: seed,
        confidence: :high,
        raw: %{observation: finding.raw, validated_from: candidate.id}
    }
  end

  defp open_port?(%Host{} = host, details) do
    Enum.any?(host.ports, fn
      %Port{number: port, protocol: protocol, state: "open"} ->
        port == details.port and normalize_protocol(protocol) == details.protocol

      _other ->
        false
    end)
  end

  defp same_endpoint?(%Core.Finding{locus: locus}, details) do
    locus.ip == details.ip and locus.port == details.port and
      normalize_protocol(locus.protocol) == details.protocol
  end

  defp endpoint!(%Core.Finding{source: :portico, id: id, locus: locus})
       when is_binary(id) and is_map(locus) do
    ip = Map.get(locus, :ip)
    port = Map.get(locus, :port)
    protocol = normalize_protocol(Map.get(locus, :protocol))

    with true <- is_binary(ip),
         {:ok, %Target{kind: :ip} = target} <- Target.parse(ip),
         true <- is_integer(port) and port in 1..65_535,
         true <- protocol in [:tcp, :udp] do
      %{ip: target.value, port: port, protocol: protocol, target: target}
    else
      _other -> raise ArgumentError, "Portico validation requires an IP, port, and protocol locus"
    end
  end

  defp endpoint!(candidate) do
    raise ArgumentError, "not a valid Portico endpoint finding: #{inspect(candidate)}"
  end

  defp replay_seed(candidate, details) do
    %Core.Seed{
      id:
        Core.Finding.dedupe_id(:portico, [
          "endpoint_validation",
          candidate.id,
          details.ip,
          details.protocol,
          details.port
        ]),
      value: %{ip: details.ip, protocol: details.protocol, port: details.port},
      classes: [:validation, :target, :endpoint],
      provenance: :promoted_finding,
      origin: {:portico, candidate.id},
      meta: %{action: @action_id}
    }
  end

  defp inconclusive(request, seed, reason) do
    Validation.inconclusive(
      request,
      seed,
      %Evidence{
        summary: "Portico could not decide the endpoint hypothesis",
        facts: %{reason: inspect(reason)},
        raw: reason
      }
    )
  end

  defp normalize_protocol(protocol) when protocol in [:tcp, "tcp", nil], do: :tcp
  defp normalize_protocol(protocol) when protocol in [:udp, "udp"], do: :udp
  defp normalize_protocol(protocol), do: protocol
end
