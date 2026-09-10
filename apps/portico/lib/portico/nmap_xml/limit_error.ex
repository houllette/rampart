defmodule Portico.NmapXML.LimitError do
  @moduledoc false
  defexception [:resource, :limit]

  @impl true
  def message(error), do: "nmap XML exceeds #{error.resource}: #{error.limit}"
end
