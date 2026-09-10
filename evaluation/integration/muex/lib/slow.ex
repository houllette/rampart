defmodule MutationFixture.Slow do
  @moduledoc false
  def read(actor) do
    if MutationFixture.Policy.authorized?(actor) do
      Process.sleep(30_000)
      :secret
    else
      :denied
    end
  end
end
