[output | files] = System.argv()

packages =
  Map.new(files, fn file ->
    {:ok, terms} = :file.consult(String.to_charlist(file))
    metadata = Map.new(terms)

    {metadata["app"],
     %{
       "version" => metadata["version"],
       "requirements" => Enum.map(metadata["requirements"], &Map.new/1)
     }}
  end)

for {app, package} <- packages, requirement <- package["requirements"] do
  case packages[requirement["app"]] do
    nil ->
      :ok

    dependency ->
      unless Version.match?(dependency["version"], requirement["requirement"]) do
        raise "#{app} cannot consume packaged #{requirement["app"]} #{dependency["version"]}"
      end
  end
end

File.write!(output, JSON.encode!(packages))
