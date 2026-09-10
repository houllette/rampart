defmodule Havoc.Observation.HTTPParameter do
  @moduledoc """
  A parsed HTTP authentication parameter tied to its intended source value.

  The parser accepts an authentication scheme followed by comma-separated
  token or quoted-string parameters. It is deliberately bounded and retains
  duplicate parameters rather than collapsing them into a map.
  """

  @max_header_bytes 16_384
  @max_parameters 128

  @type parsed_parameter :: %{name: String.t(), value: binary(), quoted?: boolean()}
  @type status :: :parsed | :malformed | :incomplete
  @type t :: %__MODULE__{
          header: binary(),
          parameter: String.t(),
          expected_value: binary(),
          input: term(),
          expected_scheme: String.t() | nil,
          scheme: String.t() | nil,
          parameters: [parsed_parameter()],
          status: status(),
          reason: atom() | nil,
          metadata: map()
        }

  @enforce_keys [
    :header,
    :parameter,
    :expected_value,
    :input,
    :parameters,
    :status,
    :metadata
  ]
  defstruct [
    :header,
    :parameter,
    :expected_value,
    :input,
    :expected_scheme,
    :scheme,
    :reason,
    parameters: [],
    status: :incomplete,
    metadata: %{}
  ]

  @doc "Parses one authentication header without assigning security meaning to it."
  @spec authentication(
          header :: binary(),
          parameter :: String.t(),
          expected_value :: binary(),
          keyword()
        ) :: t()
  def authentication(header, parameter, expected_value, opts \\ [])

  def authentication(header, parameter, expected_value, opts)
      when is_binary(header) and is_binary(parameter) and is_binary(expected_value) and
             is_list(opts) do
    opts = Keyword.validate!(opts, input: expected_value, scheme: nil, metadata: %{})
    input = opts[:input]
    expected_scheme = opts[:scheme]
    metadata = opts[:metadata]

    validate_parameter!(parameter)
    validate_scheme!(expected_scheme)
    validate_metadata!(metadata)

    normalized_parameter = ascii_downcase(parameter)

    case parse(header) do
      {:ok, scheme, parameters} ->
        %__MODULE__{
          header: header,
          parameter: normalized_parameter,
          expected_value: expected_value,
          input: input,
          expected_scheme: expected_scheme,
          scheme: scheme,
          parameters: parameters,
          status: :parsed,
          metadata: metadata
        }

      {:error, reason} ->
        %__MODULE__{
          header: header,
          parameter: normalized_parameter,
          expected_value: expected_value,
          input: input,
          expected_scheme: expected_scheme,
          parameters: [],
          status: error_status(reason),
          reason: reason,
          metadata: metadata
        }
    end
  end

  def authentication(_header, _parameter, _expected_value, _opts) do
    raise ArgumentError, "HTTP authentication observations require binary header/parameter values"
  end

  defp validate_parameter!(parameter) do
    unless parameter != "" and token?(parameter) do
      raise ArgumentError, "HTTP parameter names must be non-empty tokens"
    end
  end

  defp validate_scheme!(nil), do: :ok

  defp validate_scheme!(scheme) when is_binary(scheme) do
    unless token?(scheme), do: raise(ArgumentError, "HTTP authentication schemes must be tokens")
  end

  defp validate_scheme!(_scheme),
    do: raise(ArgumentError, "HTTP authentication schemes must be binary tokens")

  defp validate_metadata!(metadata) when is_map(metadata), do: :ok

  defp validate_metadata!(_metadata),
    do: raise(ArgumentError, "HTTP parameter metadata must be a map")

  defp error_status(reason) when reason in [:header_too_large, :too_many_parameters],
    do: :incomplete

  defp error_status(_reason), do: :malformed

  defp parse(header) when byte_size(header) > @max_header_bytes,
    do: {:error, :header_too_large}

  defp parse(header) do
    with {:ok, scheme, rest} <- take_token(header),
         {:ok, rest} <- require_whitespace(rest),
         {:ok, parameters} <- parse_parameters(trim_ows(rest), []) do
      {:ok, scheme, parameters}
    end
  end

  defp parse_parameters("", []), do: {:error, :missing_parameters}
  defp parse_parameters("", parameters), do: {:ok, Enum.reverse(parameters)}

  defp parse_parameters(_input, parameters) when length(parameters) >= @max_parameters,
    do: {:error, :too_many_parameters}

  defp parse_parameters(input, parameters) do
    with {:ok, name, rest} <- take_token(input),
         {:ok, rest} <- take_equals(trim_ows(rest)),
         {:ok, value, quoted?, rest} <- take_value(trim_ows(rest)),
         {:ok, rest} <- take_separator(trim_ows(rest)) do
      parameter = %{name: ascii_downcase(name), value: value, quoted?: quoted?}
      parse_parameters(rest, [parameter | parameters])
    end
  end

  defp take_token(input), do: take_token(input, 0)

  defp take_token(input, index) when index < byte_size(input) do
    if token_byte?(:binary.at(input, index)) do
      take_token(input, index + 1)
    else
      token_result(input, index)
    end
  end

  defp take_token(input, index), do: token_result(input, index)
  defp token_result(_input, 0), do: {:error, :expected_token}

  defp token_result(input, index) do
    <<token::binary-size(^index), rest::binary>> = input
    {:ok, token, rest}
  end

  defp require_whitespace(<<byte, rest::binary>>) when byte in [9, 32] do
    {:ok, trim_ows(rest)}
  end

  defp require_whitespace(_input), do: {:error, :expected_scheme_whitespace}

  defp take_equals(<<"=", rest::binary>>), do: {:ok, rest}
  defp take_equals(_input), do: {:error, :expected_equals}

  defp take_value(<<"\"", rest::binary>>), do: take_quoted(rest, [])

  defp take_value(input) do
    case take_token(input) do
      {:ok, value, rest} -> {:ok, value, false, rest}
      {:error, _reason} -> {:error, :expected_parameter_value}
    end
  end

  defp take_quoted(<<"\"", rest::binary>>, acc) do
    {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary(), true, rest}
  end

  defp take_quoted(<<"\\", byte, rest::binary>>, acc)
       when byte in [9, 32] or byte in 33..126 or byte >= 128 do
    take_quoted(rest, [<<byte>> | acc])
  end

  defp take_quoted(<<byte, rest::binary>>, acc)
       when byte in [9, 32, 33] or byte in 35..91 or byte in 93..126 or byte >= 128 do
    take_quoted(rest, [<<byte>> | acc])
  end

  defp take_quoted(<<>>, _acc), do: {:error, :unterminated_quoted_string}
  defp take_quoted(_input, _acc), do: {:error, :invalid_quoted_string_byte}

  defp take_separator(""), do: {:ok, ""}
  defp take_separator(<<",", rest::binary>>), do: nonempty_parameter_tail(trim_ows(rest))
  defp take_separator(_input), do: {:error, :expected_parameter_separator}

  defp nonempty_parameter_tail(""), do: {:error, :trailing_parameter_separator}
  defp nonempty_parameter_tail(rest), do: {:ok, rest}

  defp trim_ows(<<byte, rest::binary>>) when byte in [9, 32], do: trim_ows(rest)
  defp trim_ows(rest), do: rest

  defp token?(value) when is_binary(value) and value != "" do
    value |> :binary.bin_to_list() |> Enum.all?(&token_byte?/1)
  end

  defp token?(_value), do: false

  defp token_byte?(byte) when byte in ?0..?9 or byte in ?A..?Z or byte in ?a..?z, do: true
  defp token_byte?(byte) when byte in ~c"!#$%&'*+-.^_`|~", do: true
  defp token_byte?(_byte), do: false

  defp ascii_downcase(value), do: String.downcase(value, :ascii)
end
