defmodule RampartEvaluation.Runtime do
  @moduledoc false

  @spec provenance() :: map()
  def provenance do
    version_path =
      Path.join([to_string(:code.root_dir()), "releases", System.otp_release(), "OTP_VERSION"])

    %{
      otp_version: read_version(version_path),
      application_versions:
        Map.new([:inets, :ssh], &{Atom.to_string(&1), application_version(&1)})
    }
  end

  defp read_version(path) do
    case File.read(path) do
      {:ok, contents} -> String.trim(contents)
      {:error, _reason} -> nil
    end
  end

  defp application_version(application) do
    with file when is_binary(file) <- application_file(application),
         {:ok, [{:application, ^application, properties}]} <-
           :file.consult(String.to_charlist(file)),
         version when is_list(version) or is_binary(version) <- properties[:vsn] do
      to_string(version)
    else
      _unavailable -> nil
    end
  end

  defp application_file(application) do
    case :code.lib_dir(application) do
      path when is_list(path) ->
        Path.join([to_string(path), "ebin", "#{application}.app"])

      {:error, :bad_name} ->
        # Mix can prune an installed application's code path. Inspect only an
        # unambiguous installed candidate; never load/start it to learn its version.
        pattern =
          Path.join([
            to_string(:code.root_dir()),
            "lib",
            "#{application}-*",
            "ebin",
            "#{application}.app"
          ])

        case Path.wildcard(pattern) do
          [file] -> file
          _missing_or_ambiguous -> nil
        end
    end
  end
end
