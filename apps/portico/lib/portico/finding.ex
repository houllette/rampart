defmodule Portico.Finding do
  @moduledoc "Projects rich Portico results into normalized Core findings."

  alias Portico.{Host, Port, Service}

  @doc "Returns one finding for each port whose state is exactly `\"open\"`."
  @spec from_host(Host.t()) :: [Core.Finding.t()]
  def from_host(%Host{status: :up} = host) do
    for %Port{state: "open"} = port <- host.ports do
      ip = canonical_ip(host.ip)
      service = service_name(port.service)
      protocol = canonical_protocol(port.protocol)

      struct(Core.Finding,
        id: Core.Finding.dedupe_id(:portico, ["endpoint", ip, protocol, port.number]),
        source: :portico,
        category: category(port.service),
        locus: %{
          ip: ip,
          hostname: host.hostname,
          port: port.number,
          protocol: protocol,
          service: service,
          product: service_field(port.service, :product),
          version: service_field(port.service, :version)
        },
        severity: nil,
        confidence: :high,
        evidence: evidence(port.number, protocol, service),
        raw: port,
        seed: nil,
        observed_at: host.scanned_at || DateTime.utc_now()
      )
    end
  end

  def from_host(%Host{}), do: []

  @doc false
  @spec emit(Host.t()) :: [Core.Finding.t()]
  def emit(%Host{} = host) do
    findings = from_host(host)
    Enum.each(findings, &Core.Telemetry.finding(:portico, &1))
    findings
  end

  defp canonical_ip(ip) when is_binary(ip) do
    case Portico.Target.parse(ip) do
      {:ok, %Portico.Target{kind: :ip, value: canonical}} -> canonical
      _other -> ip
    end
  end

  defp canonical_ip(ip), do: ip

  defp canonical_protocol(protocol) when protocol in [:tcp, "tcp", nil], do: :tcp
  defp canonical_protocol(protocol) when protocol in [:udp, "udp"], do: :udp
  defp canonical_protocol(protocol), do: protocol

  defp category(%Service{}), do: :exposed_service
  defp category(_service), do: :open_port

  defp service_name(%Service{name: name}), do: name
  defp service_name(_service), do: nil

  defp service_field(%Service{} = service, field), do: Map.fetch!(service, field)
  defp service_field(_service, _field), do: nil

  defp evidence(port, protocol, nil), do: "#{port}/#{protocol} open"
  defp evidence(port, protocol, service), do: "#{port}/#{protocol} open (#{service})"
end
