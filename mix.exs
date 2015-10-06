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

  defp get_application(:prod) do
    [
      applications: [
        :snmp_mib_ex,
        :pathname_ex
      ]
    ]
  end
  defp get_application(_) do
    [applications: [:logger]]
  end

  def application do
    get_application Mix.env
  end

  defp deps do
    [
      {:amrita, "~>0.4", git: "https://github.com/josephwilk/amrita.git"},
      {:meck, git: "https://github.com/eproxus/meck.git", override: true},
      {:snmp_mib_ex, git: "https://github.com/jonnystorm/snmp-mib-elixir"},
      {:pathname_ex, git: "https://github.com/jonnystorm/pathname-elixir"}
    ]
  end
end
