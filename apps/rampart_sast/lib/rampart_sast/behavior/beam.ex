defmodule RampartSAST.Behavior.BEAM do
  @moduledoc "High-recall BEAM/OTP behavior vocabulary over generic inventory facts."

  @behaviour RampartSAST.Behavior

  alias RampartSAST.Fact

  @id "rampart.beam-behaviors.v1"

  @impl true
  @spec id() :: String.t()
  def id, do: @id

  @impl true
  @spec classify(Fact.t(), keyword()) :: [RampartSAST.Behavior.classification()]
  def classify(%Fact{kind: :call} = fact, _options) do
    module = fact.attributes.target_module
    function = fact.attributes.target_function

    []
    |> add(fact.attributes.resolution == :dynamic_dispatch, :dynamic_dispatch, :dynamic_receiver)
    |> add(message_send?(module, function), :process_message_send, :known_api)
    |> add(otp_request?(module, function), :otp_request, :known_api)
    |> add(shared_state?(module), :shared_state_access, :module_family)
    |> add(process_state?(module, function), :process_state_access, :known_api)
    |> add(filesystem?(module), :filesystem_access, :module_family)
    |> add(network?(module), :network_access, :module_family)
    |> add(external_process?(module, function), :external_process, :known_api)
    |> add(native_code?(module, function), :native_code_boundary, :known_api)
    |> add(dynamic_code?(module, function), :dynamic_code, :known_api)
    |> add(configuration?(module, function), :configuration_read, :known_api)
    |> add(environment?(module, function), :environment_read, :known_api)
    |> add(deserialization?(module, function), :deserialization, :known_api)
    |> add(cryptography?(module), :cryptography, :module_family)
    |> add(randomness?(module, function), :randomness, :known_api)
    |> add(resource_amplification?(module, function), :resource_amplification, :known_api)
    |> Enum.reverse()
  end

  def classify(%Fact{kind: :unqualified_call} = fact, _options) do
    function = fact.attributes.target_function

    []
    |> add(function == "send", :process_message_send, :unqualified_name)
    |> add(function == "open_port", :external_process, :unqualified_name)
    |> add(
      function in ["apply", "spawn", "spawn_link", "spawn_monitor"],
      :dynamic_dispatch,
      :unqualified_name
    )
    |> Enum.reverse()
  end

  def classify(%Fact{kind: :definition} = fact, _options) do
    function =
      fact.object |> String.split(".") |> List.last() |> String.split("/") |> List.first()

    []
    |> add(
      Regex.match?(~r/authoriz|permit|allowed|can_/, function),
      :authorization_boundary,
      :function_name
    )
    |> add(
      Regex.match?(~r/authenticat|login|sign_in|verify_credential/, function),
      :authentication_boundary,
      :function_name
    )
    |> Enum.reverse()
  end

  def classify(%Fact{kind: :dependency} = fact, _options) do
    source = Map.get(fact.attributes, :source)
    add([], source in [:git, :github, :path], :non_registry_dependency, :dependency_source)
  end

  def classify(_fact, _options), do: []

  defp add(classifications, true, behavior, basis) do
    [%{behavior: behavior, basis: basis} | classifications]
  end

  defp add(classifications, false, _behavior, _basis), do: classifications

  defp message_send?(module, function) do
    {module, function} in [
      {"Kernel", "send"},
      {"Process", "send"},
      {"erlang", "send"},
      {"GenServer", "cast"},
      {"gen_server", "cast"}
    ]
  end

  defp otp_request?(module, function) do
    {module, function} in [
      {"GenServer", "call"},
      {"gen_server", "call"},
      {"Supervisor", "start_child"},
      {"DynamicSupervisor", "start_child"}
    ]
  end

  defp shared_state?(module), do: module in ["ets", "dets", "mnesia", "persistent_term"]

  defp process_state?(module, function) do
    module in ["Process", "erlang"] and function in ["get", "put", "delete", "get_keys"]
  end

  defp filesystem?(module),
    do: module in ["File", "Path", "file", "filelib", "zip", "erl_tar"]

  defp network?(module) do
    module in [
      "gen_tcp",
      "gen_udp",
      "ssl",
      "httpc",
      "Req",
      "Finch",
      "Mint.HTTP",
      "HTTPoison",
      "Tesla",
      "Bandit",
      "Plug.Conn"
    ]
  end

  defp external_process?(module, function) do
    module in ["System", "os", "Port"] and
      function in ["cmd", "shell", "open", "spawn", "spawn_executable"]
  end

  defp native_code?(module, function) do
    {module, function} in [
      {"erlang", "load_nif"},
      {"Rustler", "load_nif"},
      {"Code", "prepend_path"},
      {"code", "load_binary"}
    ]
  end

  defp dynamic_code?(module, function) do
    module in ["Code", "EEx", "erl_eval"] and
      function in ["eval_file", "eval_quoted", "eval_string", "expr", "exprs"]
  end

  defp configuration?(module, function) do
    module in ["Application", "application"] and
      function in ["get_env", "fetch_env", "fetch_env!", "get_all_env"]
  end

  defp environment?(module, function) do
    module in ["System", "os"] and function in ["get_env", "getenv"]
  end

  defp deserialization?(module, function) do
    {module, function} in [
      {"erlang", "binary_to_term"},
      {"Jason", "decode"},
      {"Jason", "decode!"},
      {"jiffy", "decode"},
      {"jsx", "decode"},
      {"yaml_elixir", "read_from_string"},
      {"YamlElixir", "read_from_string"}
    ]
  end

  defp cryptography?(module) do
    module in ["crypto", "public_key", "Plug.Crypto", "Pbkdf2", "Argon2", "Bcrypt"]
  end

  defp randomness?(module, function) do
    module in ["rand", "crypto"] and
      function in ["uniform", "bytes", "strong_rand_bytes", "rand_seed"]
  end

  defp resource_amplification?(module, function) do
    {module, function} in [
      {"Enum", "to_list"},
      {"Enum", "map"},
      {"Enum", "flat_map"},
      {"String", "duplicate"},
      {"List", "duplicate"},
      {"binary", "copy"},
      {"zlib", "uncompress"},
      {"zip", "extract"},
      {"erl_tar", "extract"}
    ]
  end
end
