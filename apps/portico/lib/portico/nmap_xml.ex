defmodule Portico.NmapXML do
  @moduledoc "Streaming Saxy handler for nmap XML output."

  @behaviour Saxy.Handler

  alias Portico.{Host, Hostname, OSClass, OSMatch, Port, Script, Service}
  alias Portico.Script.Node

  defmodule Acc do
    @moduledoc "Parser accumulator; useful for advanced streaming integrations."

    @type t :: %__MODULE__{}

    defstruct hosts: [],
              current_host: nil,
              current_port: nil,
              current_script: nil,
              current_os_match: nil,
              current_os_class: nil,
              node_stack: [],
              cpe: nil,
              scanned_at: nil,
              collect?: true,
              on_host: nil
  end

  @doc "Parses a lazy nmap XML chunk enumerable."
  @spec parse_stream(Enumerable.t(), keyword()) :: {:ok, [Host.t()]} | {:error, term()}
  def parse_stream(stream, opts \\ []) do
    acc = new_acc(opts)

    case Saxy.parse_stream(stream, __MODULE__, acc, character_data_max_length: 65_535) do
      {:ok, parsed} -> {:ok, Enum.reverse(parsed.hosts)}
      {:error, reason} -> {:error, reason}
      {:halt, parsed, _rest} -> {:ok, Enum.reverse(parsed.hosts)}
    end
  end

  @doc "Parses a complete nmap XML document."
  @spec parse_string(String.t(), keyword()) :: {:ok, [Host.t()]} | {:error, term()}
  def parse_string(xml, opts \\ []) do
    acc = new_acc(opts)

    case Saxy.parse_string(xml, __MODULE__, acc) do
      {:ok, parsed} -> {:ok, Enum.reverse(parsed.hosts)}
      {:error, reason} -> {:error, reason}
      {:halt, parsed, _rest} -> {:ok, Enum.reverse(parsed.hosts)}
    end
  end

  @impl true
  def handle_event(:start_element, {name, attributes}, acc) do
    {:ok, start_element(name, Map.new(attributes), acc)}
  end

  def handle_event(:end_element, name, acc), do: {:ok, end_element(name, acc)}
  def handle_event(:characters, characters, acc), do: {:ok, characters(characters, acc)}
  def handle_event(:cdata, characters, acc), do: {:ok, characters(characters, acc)}
  def handle_event(_event, _data, acc), do: {:ok, acc}

  defp new_acc(opts) do
    %Acc{
      scanned_at: Keyword.get(opts, :scanned_at, DateTime.utc_now()),
      collect?: Keyword.get(opts, :collect, true),
      on_host: Keyword.get(opts, :on_host)
    }
  end

  defp start_element("host", attributes, acc) do
    meta =
      %{}
      |> maybe_put("started_at_epoch", integer(attributes["starttime"]))
      |> maybe_put("ended_at_epoch", integer(attributes["endtime"]))

    %{acc | current_host: %Host{scanned_at: acc.scanned_at, meta: meta}}
  end

  defp start_element("status", attributes, %{current_host: %Host{} = host} = acc) do
    status = status(attributes["state"])
    meta = maybe_put(host.meta, "status_reason", attributes["reason"])
    %{acc | current_host: %{host | status: status, meta: meta}}
  end

  defp start_element("address", attributes, %{current_host: %Host{} = host} = acc) do
    type = attributes["addrtype"]
    address = attributes["addr"]

    addresses =
      if type && address, do: Map.put(host.addresses, type, address), else: host.addresses

    ip = if type in ["ipv4", "ipv6"], do: address, else: host.ip
    %{acc | current_host: %{host | ip: ip || host.ip, addresses: addresses}}
  end

  defp start_element("hostname", attributes, %{current_host: %Host{} = host} = acc) do
    hostname = %Hostname{name: attributes["name"], type: attributes["type"]}

    %{
      acc
      | current_host: %{
          host
          | hostname: host.hostname || hostname.name,
            hostnames: [hostname | host.hostnames]
        }
    }
  end

  defp start_element("port", attributes, acc) do
    port = %Port{
      number: integer(attributes["portid"]),
      protocol: protocol(attributes["protocol"])
    }

    %{acc | current_port: port}
  end

  defp start_element("state", attributes, %{current_port: %Port{} = port} = acc) do
    %{
      acc
      | current_port: %{
          port
          | state: attributes["state"],
            reason: attributes["reason"]
        }
    }
  end

  defp start_element("service", attributes, acc) do
    service = %Service{
      name: attributes["name"],
      product: attributes["product"],
      version: attributes["version"],
      extra_info: attributes["extrainfo"],
      tunnel: attributes["tunnel"],
      method: attributes["method"],
      confidence: integer(attributes["conf"]),
      hostname: attributes["hostname"],
      operating_system: attributes["ostype"],
      device_type: attributes["devicetype"],
      rpc_number: attributes["rpcnum"]
    }

    %{acc | current_port: put_service(acc.current_port, service)}
  end

  defp start_element("script", attributes, acc) do
    %{
      acc
      | current_script: %Script{id: attributes["id"], output: attributes["output"]},
        node_stack: []
    }
  end

  defp start_element("table", attributes, %{current_script: %Script{}} = acc) do
    push_node(acc, %Node{type: :table, key: attributes["key"]})
  end

  defp start_element("elem", attributes, %{current_script: %Script{}} = acc) do
    push_node(acc, %Node{type: :element, key: attributes["key"], value: ""})
  end

  defp start_element("cpe", _attributes, acc) do
    context = if acc.current_os_class, do: :os_class, else: :service
    %{acc | cpe: {context, []}}
  end

  defp start_element("osmatch", attributes, acc) do
    os_match = %OSMatch{
      name: attributes["name"],
      accuracy: integer(attributes["accuracy"]),
      line: integer(attributes["line"])
    }

    %{acc | current_os_match: os_match}
  end

  defp start_element("osclass", attributes, acc) do
    os_class = %OSClass{
      type: attributes["type"],
      vendor: attributes["vendor"],
      family: attributes["osfamily"],
      generation: attributes["osgen"],
      accuracy: integer(attributes["accuracy"])
    }

    %{acc | current_os_class: os_class}
  end

  defp start_element(_name, _attributes, acc), do: acc

  defp characters(characters, %{cpe: {context, chunks}} = acc) do
    %{acc | cpe: {context, [characters | chunks]}}
  end

  defp characters(characters, %{node_stack: [%Node{type: :element} = node | rest]} = acc) do
    %{acc | node_stack: [%{node | value: node.value <> characters} | rest]}
  end

  defp characters(_characters, acc), do: acc

  defp end_element("cpe", %{cpe: {context, chunks}} = acc) do
    cpe = chunks |> Enum.reverse() |> IO.iodata_to_binary() |> String.trim()
    acc = %{acc | cpe: nil}
    put_cpe(acc, context, cpe)
  end

  defp end_element(name, acc) when name in ["table", "elem"], do: pop_node(acc)

  defp end_element("script", %{current_script: %Script{} = script} = acc) do
    script = %{script | data: Enum.reverse(script.data)}
    acc = %{acc | current_script: nil, node_stack: []}
    attach_script(acc, script)
  end

  defp end_element("port", %{current_port: %Port{} = port, current_host: %Host{} = host} = acc) do
    port = %{port | scripts: Enum.reverse(port.scripts)}
    %{acc | current_port: nil, current_host: %{host | ports: [port | host.ports]}}
  end

  defp end_element("osclass", %{current_os_class: %OSClass{} = os_class} = acc) do
    os_class = %{os_class | cpes: Enum.reverse(os_class.cpes)}
    os_match = %{acc.current_os_match | classes: [os_class | acc.current_os_match.classes]}
    %{acc | current_os_class: nil, current_os_match: os_match}
  end

  defp end_element(
         "osmatch",
         %{current_os_match: %OSMatch{} = os_match, current_host: %Host{} = host} = acc
       ) do
    os_match = %{os_match | classes: Enum.reverse(os_match.classes)}

    %{
      acc
      | current_os_match: nil,
        current_host: %{host | os_matches: [os_match | host.os_matches]}
    }
  end

  defp end_element("host", %{current_host: %Host{} = host} = acc) do
    host = %{
      host
      | hostnames: Enum.reverse(host.hostnames),
        ports: Enum.reverse(host.ports),
        scripts: Enum.reverse(host.scripts),
        os_matches: Enum.reverse(host.os_matches)
    }

    maybe_emit(acc.on_host, host)
    hosts = if acc.collect?, do: [host | acc.hosts], else: acc.hosts
    %{acc | current_host: nil, hosts: hosts}
  end

  defp end_element(_name, acc), do: acc

  defp push_node(acc, node), do: %{acc | node_stack: [node | acc.node_stack]}

  defp pop_node(%{node_stack: [node | rest]} = acc) do
    node = %{node | children: Enum.reverse(node.children), value: normalize_node_value(node)}

    case rest do
      [parent | ancestors] ->
        parent = %{parent | children: [node | parent.children]}
        %{acc | node_stack: [parent | ancestors]}

      [] ->
        script = %{acc.current_script | data: [node | acc.current_script.data]}
        %{acc | current_script: script, node_stack: []}
    end
  end

  defp pop_node(acc), do: acc

  defp normalize_node_value(%Node{type: :table}), do: nil
  defp normalize_node_value(%Node{value: value}) when is_binary(value), do: String.trim(value)
  defp normalize_node_value(_node), do: nil

  defp put_cpe(acc, _context, ""), do: acc

  defp put_cpe(%{current_os_class: %OSClass{} = os_class} = acc, :os_class, cpe) do
    %{acc | current_os_class: %{os_class | cpes: [cpe | os_class.cpes]}}
  end

  defp put_cpe(%{current_port: %Port{service: %Service{} = service} = port} = acc, :service, cpe) do
    service = %{service | cpes: [cpe | service.cpes]}
    %{acc | current_port: %{port | service: service}}
  end

  defp put_cpe(acc, _context, _cpe), do: acc

  defp attach_script(%{current_port: %Port{} = port} = acc, script) do
    %{acc | current_port: %{port | scripts: [script | port.scripts]}}
  end

  defp attach_script(%{current_host: %Host{} = host} = acc, script) do
    %{acc | current_host: %{host | scripts: [script | host.scripts]}}
  end

  defp attach_script(acc, _script), do: acc

  defp put_service(%Port{} = port, service), do: %{port | service: service}
  defp put_service(nil, _service), do: nil

  defp maybe_emit(nil, _host), do: :ok

  defp maybe_emit(callback, host) when is_function(callback, 1) do
    case callback.(host) do
      :ok -> :ok
      other -> raise "nmap XML host callback returned #{inspect(other)}, expected :ok"
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp integer(nil), do: nil

  defp integer(value) do
    case Integer.parse(value) do
      {integer, ""} -> integer
      _other -> nil
    end
  end

  defp protocol("tcp"), do: :tcp
  defp protocol("udp"), do: :udp
  defp protocol(protocol), do: protocol

  defp status("up"), do: :up
  defp status("down"), do: :down
  defp status(_status), do: :unknown
end
