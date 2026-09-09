defmodule Portico.Target do
  @moduledoc "A normalized scan target used by scope policies and engines."

  @type kind :: :ip | :cidr | :hostname

  @type t :: %__MODULE__{
          original: String.t(),
          value: String.t(),
          kind: kind(),
          address: :inet.ip_address() | nil,
          prefix: non_neg_integer() | nil,
          bits: 32 | 128 | nil
        }

  @enforce_keys [:original, :value, :kind]
  defstruct [:original, :value, :kind, :address, :prefix, :bits]

  @doc "Parses an IP address, CIDR, or hostname without resolving DNS."
  @spec parse(String.t()) :: {:ok, t()} | {:error, term()}
  def parse(value) when is_binary(value) do
    value = String.trim(value)

    cond do
      value == "" ->
        {:error, :empty_target}

      String.contains?(value, "/") ->
        parse_cidr(value)

      true ->
        parse_address_or_hostname(value)
    end
  end

  def parse(value), do: {:error, {:invalid_target, value}}

  @doc "Parses a target and raises `ArgumentError` when it is invalid."
  @spec parse!(String.t()) :: t()
  def parse!(value) do
    case parse(value) do
      {:ok, target} ->
        target

      {:error, reason} ->
        raise ArgumentError, "invalid target #{inspect(value)}: #{inspect(reason)}"
    end
  end

  @doc "Returns the argument passed to an external scanner."
  @spec to_arg(t()) :: String.t()
  def to_arg(%__MODULE__{value: value}), do: value

  defp parse_cidr(value) do
    case String.split(value, "/", parts: 2) do
      [address_string, prefix_string] ->
        with {:ok, address} <- parse_address(address_string),
             {prefix, ""} <- Integer.parse(prefix_string),
             bits <- address_bits(address),
             true <- prefix in 0..bits do
          canonical_address = address |> :inet.ntoa() |> List.to_string()

          {:ok,
           %__MODULE__{
             original: value,
             value: canonical_address <> "/" <> Integer.to_string(prefix),
             kind: :cidr,
             address: address,
             prefix: prefix,
             bits: bits
           }}
        else
          false -> {:error, :invalid_prefix}
          :error -> {:error, :invalid_prefix}
          {:error, _reason} = error -> error
          _other -> {:error, :invalid_prefix}
        end

      _other ->
        {:error, :invalid_cidr}
    end
  end

  defp parse_address_or_hostname(value) do
    case parse_address(value) do
      {:ok, address} ->
        bits = address_bits(address)
        canonical = address |> :inet.ntoa() |> List.to_string()

        {:ok,
         %__MODULE__{
           original: value,
           value: canonical,
           kind: :ip,
           address: address,
           prefix: bits,
           bits: bits
         }}

      {:error, :invalid_address} ->
        parse_hostname(value)
    end
  end

  defp parse_address(value) do
    case :inet.parse_strict_address(String.to_charlist(value)) do
      {:ok, address} -> {:ok, address}
      {:error, :einval} -> {:error, :invalid_address}
    end
  end

  defp parse_hostname(value) do
    valid? =
      byte_size(value) <= 253 and
        String.match?(
          value,
          ~r/^(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$/
        )

    if valid? do
      {:ok,
       %__MODULE__{
         original: value,
         value: value |> String.trim_trailing(".") |> String.downcase(),
         kind: :hostname
       }}
    else
      {:error, :invalid_hostname}
    end
  end

  defp address_bits(address) when tuple_size(address) == 4, do: 32
  defp address_bits(address) when tuple_size(address) == 8, do: 128
end
