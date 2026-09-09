defmodule Foray.Fuzz.Engine do
  @moduledoc "Behaviour implemented by one-process-per-job web-fuzzing engines."

  alias Foray.Job

  @callback option_schema() :: keyword()
  @callback capabilities() :: [atom()]
  @callback validate_runtime(keyword()) :: :ok | {:error, term()}
  @callback stream(Job.t(), keyword()) :: Enumerable.t(Core.Finding.t())

  @optional_callbacks capabilities: 0, validate_runtime: 1
end
