defmodule Havoc.Observation.FieldPolicy do
  @moduledoc """
  Actor-paired visibility observations across equivalent protected-field paths.

  Path adapters must derive `:hidden` versus `{:visible, value}` directly from
  the returned value at the tested API boundary. They must not ask the policy
  implementation under test whether the access should have been allowed.
  """

  @max_fields 32
  @max_paths 32
  @max_accesses 256
  @max_name_bytes 128

  @type access :: :hidden | {:visible, term()}
  @type field :: atom() | String.t()
  @type path_name :: atom() | String.t()
  @type path :: %{
          required(:name) => path_name(),
          required(:privileged) => %{required(field()) => access()},
          required(:restricted) => %{required(field()) => access()}
        }
  @type t :: %__MODULE__{
          input: term(),
          privileged_actor: term(),
          restricted_actor: term(),
          protected_fields: [field()],
          paths: [path()],
          metadata: map()
        }

  @enforce_keys [
    :input,
    :privileged_actor,
    :restricted_actor,
    :protected_fields,
    :paths,
    :metadata
  ]
  defstruct @enforce_keys

  @doc "Marks a protected field as absent or redacted at the observed boundary."
  @spec hidden() :: :hidden
  def hidden, do: :hidden

  @doc "Marks a protected field as materially visible at the observed boundary."
  @spec visible(value :: term()) :: {:visible, term()}
  def visible(value), do: {:visible, value}

  @doc "Builds a validated actor/path matrix without evaluating its policy meaning."
  @spec new!(keyword()) :: t()
  def new!(attributes) when is_list(attributes) do
    attributes =
      Keyword.validate!(attributes,
        input: nil,
        privileged_actor: nil,
        restricted_actor: nil,
        protected_fields: [],
        paths: [],
        metadata: %{}
      )

    observation = struct!(__MODULE__, attributes)

    if valid_fields?(observation.protected_fields) and valid_paths?(observation.paths) and
         is_map(observation.metadata) do
      observation
    else
      raise ArgumentError, "invalid field-policy observation: #{inspect(observation)}"
    end
  end

  defp valid_fields?([_first | _rest] = fields) do
    length(fields) <= @max_fields and Enum.all?(fields, &valid_name?/1) and
      length(fields) == length(Enum.uniq(fields))
  end

  defp valid_fields?(_fields), do: false

  defp valid_paths?([_first | _rest] = paths) do
    length(paths) <= @max_paths and Enum.all?(paths, &valid_path?/1) and
      unique_path_names?(paths) and access_count(paths) <= @max_accesses
  end

  defp valid_paths?(_paths), do: false

  defp unique_path_names?(paths) do
    names = Enum.map(paths, & &1.name)
    length(names) == length(Enum.uniq(names))
  end

  defp access_count(paths) do
    Enum.reduce(paths, 0, &(map_size(&1.privileged) + map_size(&1.restricted) + &2))
  end

  defp valid_path?(%{name: name, privileged: privileged, restricted: restricted}) do
    valid_name?(name) and valid_access_map?(privileged) and valid_access_map?(restricted)
  end

  defp valid_path?(_path), do: false

  defp valid_access_map?(accesses) when is_map(accesses) do
    Enum.all?(accesses, fn {field, access} -> valid_name?(field) and valid_access?(access) end)
  end

  defp valid_access_map?(_accesses), do: false

  defp valid_access?(:hidden), do: true
  defp valid_access?({:visible, _value}), do: true
  defp valid_access?(_access), do: false

  defp valid_name?(name) when is_atom(name), do: true

  defp valid_name?(name) when is_binary(name),
    do: name != "" and byte_size(name) <= @max_name_bytes

  defp valid_name?(_name), do: false
end
