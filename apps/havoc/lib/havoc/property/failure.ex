defmodule Havoc.Property.Failure do
  @moduledoc "Structured result used by Havoc generation backends before reporting a violation."

  @type kind :: :violation | :test_exception
  @type t :: %__MODULE__{
          kind: kind(),
          payload: term(),
          observation: term(),
          violations: [Havoc.Oracle.Violation.t()] | nil,
          exception: term(),
          raise_kind: :error | :exit | :throw | nil,
          stacktrace: Exception.stacktrace() | nil
        }

  @enforce_keys [:kind, :payload]
  defstruct [
    :kind,
    :payload,
    :observation,
    :violations,
    :exception,
    :raise_kind,
    :stacktrace
  ]
end
