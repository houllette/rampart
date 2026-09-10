defmodule RampartSAST.Behavior.Plug do
  @moduledoc "High-recall, package-specific behavior vocabulary for reviewed Plug APIs."

  @behaviour RampartSAST.Behavior

  alias RampartSAST.Fact

  @id "rampart.plug-behaviors.v1"

  @classifications %{
    {"Plug.Conn", "read_body"} => :http_request_body_read,
    {"Plug.Conn", "fetch_query_params"} => :http_request_parameter_parse,
    {"Plug.Conn", "send_resp"} => :http_response_write,
    {"Plug.Conn", "send_file"} => :http_file_response,
    {"Plug.Conn", "put_resp_header"} => :http_response_header_write,
    {"Plug.Conn", "put_resp_cookie"} => :http_response_cookie_write,
    {"Plug.Conn", "put_private"} => :request_private_state_write,
    {"Plug.Crypto", "sign"} => :signed_token_create,
    {"Plug.Crypto", "verify"} => :signed_token_verify,
    {"Plug.Crypto.MessageEncryptor", "encrypt"} => :encrypted_token_create,
    {"Plug.Crypto.MessageEncryptor", "decrypt"} => :encrypted_token_decrypt
  }

  @impl true
  @spec id() :: String.t()
  def id, do: @id

  @impl true
  @spec classify(Fact.t(), keyword()) :: [RampartSAST.Behavior.classification()]
  def classify(%Fact{kind: kind} = fact, _options) when kind in [:call, :unqualified_call] do
    key = {fact.attributes.target_module, fact.attributes.target_function}

    case Map.fetch(@classifications, key) do
      {:ok, behavior} -> [%{behavior: behavior, basis: :reviewed_package_api}]
      :error -> []
    end
  end

  def classify(_fact, _options), do: []
end
