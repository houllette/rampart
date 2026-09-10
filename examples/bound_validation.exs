defmodule RampartExample.BoundValidation do
  @moduledoc """
  A host-side embedding example, not a Rampart runtime or Lemieux adapter.

  The host supplies the task supervisor, binding, deadline, artifact directory,
  and byte limit. Only the subject reference is suitable for model input.
  A consumer must put its own authorization check around artifact retrieval.
  """
  alias Core.Validation.{Binding, Wire}

  @spec start(
          supervisor :: pid(),
          binding :: Binding.t(),
          reference :: map(),
          options :: keyword()
        ) :: Task.t()
  def start(supervisor, binding, reference, options) do
    Task.Supervisor.async_nolink(supervisor, fn ->
      try do
        with {:ok, result} <- Binding.invoke(binding, reference) do
          {:ok, project(result, options)}
        end
      rescue
        error in Core.Scope.Error -> {:error, {:scope_denied, Exception.message(error)}}
        error -> {:error, {:validator_crash, Exception.format_banner(:error, error)}}
      catch
        kind, reason -> {:error, {:validator_crash, Exception.format_banner(kind, reason)}}
      end
    end)
  end

  @spec await(task :: Task.t(), timeout :: pos_integer()) :: {:ok, map()} | {:error, term()}
  def await(task, timeout) do
    case Task.yield(task, timeout) do
      {:ok, result} ->
        result

      {:exit, reason} ->
        {:error, {:validator_crash, reason}}

      nil ->
        Task.shutdown(task, :brutal_kill)
        {:error, :deadline_exceeded}
    end
  end

  @spec cancel(task :: Task.t()) :: {:error, :cancelled}
  def cancel(task) do
    Task.shutdown(task, :brutal_kill)
    {:error, :cancelled}
  end

  defp project(result, options) do
    limit = Keyword.fetch!(options, :output_limit)
    directory = Keyword.fetch!(options, :artifact_directory)
    true = is_integer(limit) and limit > 0
    projection = Wire.result(result)
    encoded = Wire.encode!(projection)

    if byte_size(encoded) <= limit do
      projection
    else
      digest = :crypto.hash(:sha256, encoded) |> Base.encode16(case: :lower)
      File.mkdir_p!(directory)
      path = Path.join(directory, digest <> ".json")

      case File.write(path, encoded, [:exclusive]) do
        :ok ->
          :ok

        {:error, :eexist} ->
          unless File.read!(path) == encoded, do: raise("artifact integrity mismatch")

        {:error, reason} ->
          raise File.Error, reason: reason, action: "write artifact", path: path
      end

      summary = %{
        "schema_version" => 1,
        "id" => result.id,
        "action_id" => result.action.id,
        "verdict" => Atom.to_string(result.verdict),
        "seed_id" => result.seed.id,
        "artifact" => %{"sha256" => digest, "size_bytes" => byte_size(encoded)},
        "full_result_externalized" => true
      }

      if byte_size(Wire.encode!(summary)) > limit do
        raise ArgumentError, "output limit cannot hold the artifact reference"
      end

      summary
    end
  end
end
