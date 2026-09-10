defmodule RampartUpstream.MintCheck do
  @moduledoc false

  alias Core.Seed
  alias Core.Validation.Wire

  def run! do
    mode = System.fetch_env!("RAMPART_UPSTREAM_MODE")
    role = System.fetch_env!("RAMPART_UPSTREAM_ROLE")
    contract_id = System.fetch_env!("RAMPART_UPSTREAM_CONTRACT")
    output = System.fetch_env!("RAMPART_UPSTREAM_OUTPUT")

    {seed_value, target} = target(mode)

    seed = %Seed{
      id:
        Core.Finding.dedupe_id(:upstream_evaluation, [
          contract_id,
          Havoc.TermCodec.fingerprint(seed_value)
        ]),
      value: seed_value,
      classes: [:upstream_package, :resource_budget],
      provenance: :external,
      meta: %{package: "mint", revision: System.fetch_env!("RAMPART_UPSTREAM_REVISION")}
    }

    result =
      Havoc.validate(seed, target,
        oracles: [budget_oracle()],
        persist: false,
        property_id: contract_id,
        property_name: "full upstream Mint resource budget"
      )

    loaded_beam = :code.which(Mint.HTTP1) |> to_string()

    report = %{
      schema_version: 1,
      status: :passed,
      role: role,
      mode: mode,
      revision: System.fetch_env!("RAMPART_UPSTREAM_REVISION"),
      package_version: Application.spec(:mint, :vsn) |> to_string(),
      loaded_beam: loaded_beam,
      loaded_beam_sha256: loaded_beam |> File.read!() |> digest(),
      input_seed_id: seed.id,
      input_fingerprint: Havoc.TermCodec.fingerprint(seed.value),
      result: Wire.result(result)
    }

    File.write!(output, JSON.encode!(Wire.json(report)))
  end

  defp target("response_line") do
    line = "HTTP/1.1 200 " <> String.duplicate("x", 52)
    true = byte_size(line) == 65

    target = fn candidate ->
      control = probe_response_line(String.slice(candidate, 0, 64))

      unless control == %{accepted: true, reason: :incomplete} do
        raise "Mint exact-boundary positive control failed: #{inspect(control)}"
      end

      %{candidate: probe_response_line(candidate), unit: :bytes, limit: 64}
    end

    {line, target}
  end

  defp target("chunk_size") do
    digits = String.duplicate("F", 17)

    target = fn candidate ->
      control = Mint.HTTP1.Parse.chunk_size(String.slice(candidate, 0, 16) <> "\r\n")

      unless match?({:ok, 0xFFFFFFFFFFFFFFFF, "\r\n"}, control) do
        raise "Mint maximum valid chunk-size control failed: #{inspect(control)}"
      end

      result = Mint.HTTP1.Parse.chunk_size(candidate <> "\r\n")
      %{candidate: normalize_chunk_size(result), unit: :hex_digits, limit: 16}
    end

    {digits, target}
  end

  defp target(mode), do: raise(ArgumentError, "unknown upstream mode: #{inspect(mode)}")

  defp budget_oracle do
    Havoc.Oracle.custom(
      :upstream_resource_budget,
      fn observation, _payload ->
        case observation.candidate do
          %{accepted: false} -> :ok
          %{accepted: true} -> {:error, "upstream parser accepted an input beyond its budget"}
        end
      end,
      category: :resource_exhaustion,
      confidence: :high
    )
  end

  defp probe_response_line(line) do
    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        ip: {127, 0, 0, 1}
      ])

    {:ok, {_address, port}} = :inet.sockname(listener)
    parent = self()

    acceptor =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener)
        send(parent, {:accepted, self()})

        receive do
          :close -> :ok
        after
          5_000 -> :ok
        end

        :gen_tcp.close(socket)
      end)

    try do
      {:ok, conn} =
        Mint.HTTP1.connect(:http, "127.0.0.1", port,
          mode: :passive,
          max_header_list_size: 64
        )

      receive do
        {:accepted, ^acceptor} -> :ok
      after
        2_000 -> raise "Mint control listener was not accepted"
      end

      {:ok, conn, _request_ref} = Mint.HTTP1.request(conn, "GET", "/", [], nil)
      outcome = Mint.HTTP1.stream(conn, {:tcp, conn.socket, line})
      normalize_response_line(outcome)
    after
      send(acceptor, :close)
      :gen_tcp.close(listener)
    end
  end

  defp normalize_response_line({:ok, _conn, []}), do: %{accepted: true, reason: :incomplete}

  defp normalize_response_line(
         {:error, _conn, %Mint.HTTPError{reason: {:response_line_too_long, size, maximum}}, []}
       ) do
    %{accepted: false, reason: :response_line_too_long, size: size, maximum: maximum}
  end

  defp normalize_response_line(other) do
    raise "unexpected Mint response-line result: #{inspect(other)}"
  end

  defp normalize_chunk_size(:error), do: %{accepted: false, reason: :invalid_chunk_size}
  defp normalize_chunk_size({:ok, value, "\r\n"}), do: %{accepted: true, value: value}

  defp normalize_chunk_size(other) do
    raise "unexpected Mint chunk-size result: #{inspect(other)}"
  end

  defp digest(binary),
    do: binary |> then(&:crypto.hash(:sha256, &1)) |> Base.encode16(case: :lower)
end

RampartUpstream.MintCheck.run!()
