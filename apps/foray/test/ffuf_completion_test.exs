defmodule Foray.FfufCompletionTest do
  use ExUnit.Case, async: true
  alias Foray.Fuzz.Ffuf.Completion

  @tag :tmp_dir
  test "refutation requires an exact successful response receipt", %{tmp_dir: directory} do
    completion = %{
      path: Path.join(directory, "audit.jsonl"),
      inputs: %{"FUZZ" => "admin"},
      method: "GET"
    }

    receipt = %{
      "Type" => "*ffuf.Response",
      "Data" => %{
        "StatusCode" => 404,
        "Cancelled" => false,
        "Request" => %{
          "Method" => "GET",
          "Error" => "",
          "Input" => %{"FUZZ" => Base.encode64("admin")}
        }
      }
    }

    File.write!(completion.path, Jason.encode!(receipt) <> "\n")
    assert Enum.to_list(Completion.stdout([{:stdout, "match\n"}], completion)) == ["match\n"]

    for bad <- [
          put_in(receipt, ["Data", "Cancelled"], true),
          put_in(receipt, ["Data", "Request", "Error"], "timeout"),
          put_in(receipt, ["Data", "Request", "Method"], "POST"),
          put_in(receipt, ["Data", "Request", "Input", "FUZZ"], Base.encode64("other"))
        ] do
      File.write!(completion.path, Jason.encode!(bad) <> "\n")
      assert_raise Foray.OutputError, fn -> Enum.to_list(Completion.stdout([], completion)) end
    end
  end

  @tag :tmp_dir
  test "missing, malformed, or oversized audit data cannot prove completion", %{
    tmp_dir: directory
  } do
    completion = %{
      path: Path.join(directory, "audit.jsonl"),
      inputs: %{"FUZZ" => "admin"},
      method: "GET"
    }

    assert_raise Foray.OutputError, fn -> Enum.to_list(Completion.stdout([], completion)) end

    for data <- ["", "{broken", String.duplicate("x", 16_777_217)] do
      File.write!(completion.path, data)
      assert_raise Foray.OutputError, fn -> Enum.to_list(Completion.stdout([], completion)) end
    end
  end

  test "a concrete match can stop execution without requiring an unobserved receipt" do
    assert Enum.take(Completion.stdout([{:stdout, "match\n"}], %{path: "absent"}), 1) == [
             "match\n"
           ]
  end
end
