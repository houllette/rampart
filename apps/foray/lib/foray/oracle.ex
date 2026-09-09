defmodule Foray.Oracle do
  @moduledoc "Typed matcher/filter configuration defining which ffuf responses become findings."

  @type set_mode :: :and | :or
  @type criteria :: %{
          optional(:codes) => :all | [integer() | Range.t()],
          optional(:lines) => integer() | [integer() | Range.t()],
          optional(:regex) => String.t(),
          optional(:size) => integer() | [integer() | Range.t()],
          optional(:time) => {:gt | :lt, non_neg_integer()},
          optional(:words) => integer() | [integer() | Range.t()]
        }

  @type t :: %__MODULE__{
          matchers: criteria(),
          filters: criteria(),
          matcher_mode: set_mode(),
          filter_mode: set_mode(),
          auto_calibrate: boolean(),
          calibration_strings: [String.t()]
        }

  defstruct matchers: %{},
            filters: %{},
            matcher_mode: :or,
            filter_mode: :or,
            auto_calibrate: false,
            calibration_strings: []
end
