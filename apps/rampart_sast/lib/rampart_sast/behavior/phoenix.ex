defmodule RampartSAST.Behavior.Phoenix do
  @moduledoc "High-recall, package-specific behavior vocabulary for reviewed Phoenix APIs."

  @behaviour RampartSAST.Behavior

  alias RampartSAST.Fact

  @id "rampart.phoenix-behaviors.v1"

  @classifications %{
    {"Phoenix.Controller", "redirect"} => :http_redirect,
    {"Phoenix.Controller", "render"} => :http_response_render,
    {"Phoenix.Controller", "json"} => :http_json_response,
    {"Phoenix.Controller", "send_download"} => :http_file_response,
    {"Phoenix.Controller", "put_secure_browser_headers"} => :http_security_headers,
    {"Phoenix.LiveView", "redirect"} => :live_navigation,
    {"Phoenix.LiveView", "push_navigate"} => :live_navigation,
    {"Phoenix.LiveView", "push_patch"} => :live_navigation,
    {"Phoenix.LiveView", "push_event"} => :live_client_event,
    {"Phoenix.LiveView", "allow_upload"} => :file_upload_configuration,
    {"Phoenix.LiveView", "consume_uploaded_entries"} => :file_upload_consumption,
    {"Phoenix.Token", "sign"} => :signed_token_create,
    {"Phoenix.Token", "verify"} => :signed_token_verify
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
