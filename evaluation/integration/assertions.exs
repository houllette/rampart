Code.require_file("../runtime.exs", __DIR__)

defmodule Integration.Assertions do
  @moduledoc false
  import ExUnit.Assertions

  def finish(details \\ %{}) do
    runtime = runtime()

    File.write!(
      System.fetch_env!("RAMPART_GATE_REPORT"),
      details
      |> Map.update(:runtime, runtime, &Map.merge(&1, runtime))
      |> Map.put(:status, "passed")
      |> JSON.encode!()
    )
  end

  defp runtime do
    Map.merge(RampartEvaluation.Runtime.provenance(), %{
      elixir: System.version(),
      otp: System.otp_release(),
      erts: to_string(:erlang.system_info(:version))
    })
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
