defmodule Foray.Match do
  @moduledoc "A validated ffuf v2.2 NDJSON match record."

  @type t :: %__MODULE__{
          input: %{optional(String.t()) => String.t()},
          position: non_neg_integer(),
          status: non_neg_integer(),
          length: non_neg_integer(),
          words: non_neg_integer(),
          lines: non_neg_integer(),
          content_type: String.t(),
          redirect_location: String.t(),
          url: String.t(),
          duration_ns: non_neg_integer(),
          scraper: map(),
          result_file: String.t(),
          host: String.t(),
          raw: map()
        }

  @enforce_keys [
    :input,
    :position,
    :status,
    :length,
    :words,
    :lines,
    :content_type,
    :redirect_location,
    :url,
    :duration_ns,
    :scraper,
    :result_file,
    :host,
    :raw
  ]
  defstruct [
    :input,
    :position,
    :status,
    :length,
    :words,
    :lines,
    :content_type,
    :redirect_location,
    :url,
    :duration_ns,
    :scraper,
    :result_file,
    :host,
    :raw
  ]
end
