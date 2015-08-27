defmodule NetSNMP.Mixfile do
  use Mix.Project

  def project do
    [app: :net_snmp_ex,
     version: "0.0.1",
     elixir: "~> 1.0",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     deps: deps]
  end

  def application do
    [applications: [:logger]]
  end

  defp deps do
    [
      {:amrita, "~>0.4", git: "https://github.com/josephwilk/amrita"},
      {:meck, git: "https://github.com/eproxus/meck", branch: "master", override: true},
      {:snmp_mib_ex, git: "https://github.com/jonnystorm/snmp-mib-elixir"},
      {:pathname_ex, git: "https://github.com/jonnystorm/pathname-elixir"}
    ]
  end
end
