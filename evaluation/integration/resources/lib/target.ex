defmodule ResourceFixture.Sink do
  @moduledoc false
  def observe(value), do: value
end

defmodule ResourceFixture.Target do
  @moduledoc false
  def run(:compute, marker) do
    Enum.reduce(1..100_000, 0, &Bitwise.bxor(&1, &2))
    ResourceFixture.Sink.observe(marker)
  end

  def run(:binary, marker), do: ResourceFixture.Sink.observe(:binary.copy("x", 50_000) <> marker)

  def run(:container, marker),
    do: ResourceFixture.Sink.observe(%{items: List.duplicate({:item, 7}, 1000), marker: marker})

  def run(:io, marker) do
    path =
      Path.join(
        System.tmp_dir!(),
        "rampart-io-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    try do
      File.write!(path, :binary.copy("x", 32_000) <> marker)
      ResourceFixture.Sink.observe(File.read!(path))
    after
      File.rm!(path)
    end
  end
end
