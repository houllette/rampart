defmodule Portico.Discovery.Engine do
  @moduledoc "Behaviour implemented by fast host/port discovery engines."

  alias Portico.{Discovery.Result, Target}

  @callback option_schema() :: keyword()
  @callback capabilities() :: map()
  @callback validate_runtime(keyword()) :: :ok | {:error, term()}
  @callback stream(Target.t(), keyword()) :: Enumerable.t(Result.t())

  @optional_callbacks capabilities: 0, validate_runtime: 1
end
