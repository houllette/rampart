defmodule Portico.Scope.Allowlist do
  @moduledoc """
  A fail-closed IP/CIDR allowlist policy.

  Hostnames are rejected by default because authorizing an unresolved name does
  not constrain what a scanner may resolve later. Exact hostname authorization
  must be explicitly enabled with the `:hostnames` option, or implemented in a
  custom policy that pins DNS resolution.
  """

  @behaviour Core.Scope.Policy

  alias Portico.Scope.CIDR
  alias Portico.Target

  @type t :: %__MODULE__{
          networks: [Target.t()],
          hostnames: MapSet.t(String.t())
        }

  defstruct networks: [], hostnames: MapSet.new()

  @doc "Builds an allowlist from IP addresses and CIDRs."
  @spec new([String.t()], keyword()) :: {:ok, t()} | {:error, term()}
  def new(entries, opts \\ []) when is_list(entries) and is_list(opts) do
    with {:ok, networks} <- parse_networks(entries),
         {:ok, hostnames} <- parse_hostnames(Keyword.get(opts, :hostnames, [])) do
      {:ok, %__MODULE__{networks: networks, hostnames: MapSet.new(hostnames)}}
    end
  end

  @doc "Builds an allowlist and raises when any entry is invalid."
  @spec new!([String.t()], keyword()) :: t()
  def new!(entries, opts \\ []) do
    case new(entries, opts) do
      {:ok, allowlist} -> allowlist
      {:error, reason} -> raise ArgumentError, "invalid scope allowlist: #{inspect(reason)}"
    end
  end

  @impl true
  def authorized?(%Target{kind: :hostname, value: hostname}, %__MODULE__{} = policy) do
    MapSet.member?(policy.hostnames, hostname)
  end

  def authorized?(%Target{} = target, %__MODULE__{} = policy) do
    Enum.any?(policy.networks, &CIDR.contains?(&1, target))
  end

  def authorized?(_target, %__MODULE__{}), do: false

  defp parse_networks(entries) do
    Enum.reduce_while(entries, {:ok, []}, fn entry, {:ok, acc} ->
      case Target.parse(entry) do
        {:ok, %Target{kind: kind} = target} when kind in [:ip, :cidr] ->
          {:cont, {:ok, [target | acc]}}

        {:ok, %Target{kind: :hostname}} ->
          {:halt, {:error, {:hostname_requires_explicit_option, entry}}}

        {:error, reason} ->
          {:halt, {:error, {entry, reason}}}
      end
    end)
    |> case do
      {:ok, targets} -> {:ok, Enum.reverse(targets)}
      error -> error
    end
  end

  defp parse_hostnames(hostnames) when is_list(hostnames) do
    Enum.reduce_while(hostnames, {:ok, []}, fn hostname, {:ok, acc} ->
      case Target.parse(hostname) do
        {:ok, %Target{kind: :hostname, value: value}} -> {:cont, {:ok, [value | acc]}}
        {:ok, _target} -> {:halt, {:error, {:not_a_hostname, hostname}}}
        {:error, reason} -> {:halt, {:error, {hostname, reason}}}
      end
    end)
  end

  defp parse_hostnames(other), do: {:error, {:invalid_hostnames, other}}
end
