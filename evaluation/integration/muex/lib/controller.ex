defmodule MutationFixture.Policy do
  @moduledoc false
  def authorized?(actor), do: actor == :admin
end

defmodule MutationFixture.Controller do
  @moduledoc false
  def read(actor) do
    if MutationFixture.Policy.authorized?(actor), do: :secret, else: :denied
  end
end
