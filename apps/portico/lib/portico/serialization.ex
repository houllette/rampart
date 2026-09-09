defmodule Portico.Serialization do
  @moduledoc false

  alias Portico.{Host, Hostname, OSClass, OSMatch, Port, Script, Service}
  alias Portico.Script.Node

  @spec to_map(
          Host.t()
          | Hostname.t()
          | OSClass.t()
          | OSMatch.t()
          | Port.t()
          | Script.t()
          | Node.t()
          | Service.t()
        ) :: map()
  def to_map(%Host{} = host) do
    %{
      "schema_version" => host.schema_version,
      "ip" => host.ip,
      "hostname" => host.hostname,
      "hostnames" => Enum.map(host.hostnames, &to_map/1),
      "status" => Atom.to_string(host.status),
      "scanned_at" => encode_datetime(host.scanned_at),
      "addresses" => host.addresses,
      "ports" => Enum.map(host.ports, &to_map/1),
      "scripts" => Enum.map(host.scripts, &to_map/1),
      "os_matches" => Enum.map(host.os_matches, &to_map/1),
      "meta" => host.meta
    }
  end

  def to_map(%Hostname{} = hostname) do
    %{"name" => hostname.name, "type" => hostname.type}
  end

  def to_map(%Port{} = port) do
    %{
      "number" => port.number,
      "protocol" => encode_protocol(port.protocol),
      "state" => port.state,
      "reason" => port.reason,
      "service" => maybe_map(port.service),
      "scripts" => Enum.map(port.scripts, &to_map/1),
      "meta" => port.meta
    }
  end

  def to_map(%Service{} = service) do
    %{
      "name" => service.name,
      "product" => service.product,
      "version" => service.version,
      "extra_info" => service.extra_info,
      "tunnel" => service.tunnel,
      "method" => service.method,
      "confidence" => service.confidence,
      "hostname" => service.hostname,
      "operating_system" => service.operating_system,
      "device_type" => service.device_type,
      "rpc_number" => service.rpc_number,
      "cpes" => service.cpes
    }
  end

  def to_map(%Script{} = script) do
    %{"id" => script.id, "output" => script.output, "data" => Enum.map(script.data, &to_map/1)}
  end

  def to_map(%Node{} = node) do
    %{
      "type" => Atom.to_string(node.type),
      "key" => node.key,
      "value" => node.value,
      "children" => Enum.map(node.children, &to_map/1)
    }
  end

  def to_map(%OSMatch{} = os_match) do
    %{
      "name" => os_match.name,
      "accuracy" => os_match.accuracy,
      "line" => os_match.line,
      "classes" => Enum.map(os_match.classes, &to_map/1)
    }
  end

  def to_map(%OSClass{} = os_class) do
    %{
      "type" => os_class.type,
      "vendor" => os_class.vendor,
      "family" => os_class.family,
      "generation" => os_class.generation,
      "accuracy" => os_class.accuracy,
      "cpes" => os_class.cpes
    }
  end

  @spec host_from_map(map()) :: {:ok, Host.t()} | {:error, term()}
  def host_from_map(%{"schema_version" => 1} = map) do
    with {:ok, status} <- decode_status(map["status"]),
         {:ok, scanned_at} <- decode_datetime(map["scanned_at"]),
         {:ok, ports} <- map_list(map["ports"], &port_from_map/1),
         {:ok, scripts} <- map_list(map["scripts"], &script_from_map/1),
         {:ok, hostnames} <- map_list(map["hostnames"], &hostname_from_map/1),
         {:ok, os_matches} <- map_list(map["os_matches"], &os_match_from_map/1) do
      {:ok,
       %Host{
         schema_version: 1,
         ip: map["ip"],
         hostname: map["hostname"],
         hostnames: hostnames,
         status: status,
         scanned_at: scanned_at,
         addresses: map["addresses"] || %{},
         ports: ports,
         scripts: scripts,
         os_matches: os_matches,
         meta: map["meta"] || %{}
       }}
    end
  end

  def host_from_map(%{"schema_version" => version}),
    do: {:error, {:unsupported_schema_version, version}}

  def host_from_map(_map), do: {:error, :missing_schema_version}

  defp port_from_map(map) when is_map(map) do
    with {:ok, protocol} <- decode_protocol(map["protocol"]),
         {:ok, service} <- service_from_map(map["service"]),
         {:ok, scripts} <- map_list(map["scripts"], &script_from_map/1) do
      {:ok,
       %Port{
         number: map["number"],
         protocol: protocol,
         state: map["state"],
         reason: map["reason"],
         service: service,
         scripts: scripts,
         meta: map["meta"] || %{}
       }}
    end
  end

  defp port_from_map(other), do: {:error, {:invalid_port, other}}

  defp service_from_map(nil), do: {:ok, nil}

  defp service_from_map(map) when is_map(map) do
    {:ok,
     %Service{
       name: map["name"],
       product: map["product"],
       version: map["version"],
       extra_info: map["extra_info"],
       tunnel: map["tunnel"],
       method: map["method"],
       confidence: map["confidence"],
       hostname: map["hostname"],
       operating_system: map["operating_system"],
       device_type: map["device_type"],
       rpc_number: map["rpc_number"],
       cpes: map["cpes"] || []
     }}
  end

  defp service_from_map(other), do: {:error, {:invalid_service, other}}

  defp script_from_map(map) when is_map(map) do
    with {:ok, data} <- map_list(map["data"], &node_from_map/1) do
      {:ok, %Script{id: map["id"], output: map["output"], data: data}}
    end
  end

  defp script_from_map(other), do: {:error, {:invalid_script, other}}

  defp node_from_map(map) when is_map(map) do
    with {:ok, type} <- decode_node_type(map["type"]),
         {:ok, children} <- map_list(map["children"], &node_from_map/1) do
      {:ok, %Node{type: type, key: map["key"], value: map["value"], children: children}}
    end
  end

  defp node_from_map(other), do: {:error, {:invalid_script_node, other}}

  defp hostname_from_map(map) when is_map(map) do
    {:ok, %Hostname{name: map["name"], type: map["type"]}}
  end

  defp hostname_from_map(other), do: {:error, {:invalid_hostname, other}}

  defp os_match_from_map(map) when is_map(map) do
    with {:ok, classes} <- map_list(map["classes"], &os_class_from_map/1) do
      {:ok,
       %OSMatch{
         name: map["name"],
         accuracy: map["accuracy"],
         line: map["line"],
         classes: classes
       }}
    end
  end

  defp os_match_from_map(other), do: {:error, {:invalid_os_match, other}}

  defp os_class_from_map(map) when is_map(map) do
    {:ok,
     %OSClass{
       type: map["type"],
       vendor: map["vendor"],
       family: map["family"],
       generation: map["generation"],
       accuracy: map["accuracy"],
       cpes: map["cpes"] || []
     }}
  end

  defp os_class_from_map(other), do: {:error, {:invalid_os_class, other}}

  defp map_list(nil, _mapper), do: {:ok, []}

  defp map_list(list, mapper) when is_list(list) do
    Enum.reduce_while(list, {:ok, []}, fn item, {:ok, acc} ->
      case mapper.(item) do
        {:ok, mapped} -> {:cont, {:ok, [mapped | acc]}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
    |> reverse_ok()
  end

  defp map_list(other, _mapper), do: {:error, {:expected_list, other}}

  defp reverse_ok({:ok, list}), do: {:ok, Enum.reverse(list)}
  defp reverse_ok(error), do: error

  defp decode_status("up"), do: {:ok, :up}
  defp decode_status("down"), do: {:ok, :down}
  defp decode_status("timeout"), do: {:ok, :timeout}
  defp decode_status("error"), do: {:ok, :error}
  defp decode_status("unknown"), do: {:ok, :unknown}
  defp decode_status(other), do: {:error, {:invalid_status, other}}

  defp decode_protocol("tcp"), do: {:ok, :tcp}
  defp decode_protocol("udp"), do: {:ok, :udp}
  defp decode_protocol(protocol) when is_binary(protocol), do: {:ok, protocol}
  defp decode_protocol(nil), do: {:ok, nil}
  defp decode_protocol(other), do: {:error, {:invalid_protocol, other}}

  defp decode_node_type("table"), do: {:ok, :table}
  defp decode_node_type("element"), do: {:ok, :element}
  defp decode_node_type(other), do: {:error, {:invalid_script_node_type, other}}

  defp decode_datetime(nil), do: {:ok, nil}

  defp decode_datetime(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _offset} -> {:ok, datetime}
      {:error, reason} -> {:error, {:invalid_scanned_at, reason}}
    end
  end

  defp decode_datetime(other), do: {:error, {:invalid_scanned_at, other}}

  defp encode_datetime(nil), do: nil
  defp encode_datetime(datetime), do: DateTime.to_iso8601(datetime)

  defp encode_protocol(protocol) when is_atom(protocol), do: Atom.to_string(protocol)
  defp encode_protocol(protocol), do: protocol

  defp maybe_map(nil), do: nil
  defp maybe_map(struct), do: to_map(struct)
end
