defmodule Integration.Assertions do
  @moduledoc false
  import ExUnit.Assertions

  def finish(details \\ %{}) do
    File.write!(
      System.fetch_env!("RAMPART_GATE_REPORT"),
      JSON.encode!(Map.put(details, :status, "passed"))
    )
  end

  def isolated! do
    expected = System.fetch_env!("RAMPART_EXPECTED_APPS") |> String.split(",")

    modules = %{
      "security_core" => Core.Validation,
      "havoc" => Havoc,
      "havoc_proper" => HavocProper,
      "foray" => Foray,
      "portico" => Portico,
      "muex_security" => MuexSecurity,
      "rampart_sast" => RampartSAST,
      "rampart_iast" => RampartIAST
    }

    for {app, module} <- modules do
      if app in expected do
        assert Code.ensure_loaded?(module), "#{app} is not usable in the consumer"
        assert module |> :code.which() |> to_string() |> String.starts_with?(File.cwd!())
      else
        refute Code.ensure_loaded?(module),
               "undeclared sister tool #{app} leaked into the consumer"
      end
    end
  end
end
