defimpl Jason.Encoder, for: Portico.Host do
  def encode(value, opts), do: Jason.Encode.map(Portico.Serialization.to_map(value), opts)
end

defimpl Jason.Encoder, for: Portico.Hostname do
  def encode(value, opts), do: Jason.Encode.map(Portico.Serialization.to_map(value), opts)
end

defimpl Jason.Encoder, for: Portico.Port do
  def encode(value, opts), do: Jason.Encode.map(Portico.Serialization.to_map(value), opts)
end

defimpl Jason.Encoder, for: Portico.Service do
  def encode(value, opts), do: Jason.Encode.map(Portico.Serialization.to_map(value), opts)
end

defimpl Jason.Encoder, for: Portico.Script do
  def encode(value, opts), do: Jason.Encode.map(Portico.Serialization.to_map(value), opts)
end

defimpl Jason.Encoder, for: Portico.Script.Node do
  def encode(value, opts), do: Jason.Encode.map(Portico.Serialization.to_map(value), opts)
end

defimpl Jason.Encoder, for: Portico.OSMatch do
  def encode(value, opts), do: Jason.Encode.map(Portico.Serialization.to_map(value), opts)
end

defimpl Jason.Encoder, for: Portico.OSClass do
  def encode(value, opts), do: Jason.Encode.map(Portico.Serialization.to_map(value), opts)
end
