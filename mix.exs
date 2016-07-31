defmodule NetSNMP.Mixfile do
  use Mix.Project

  def project do
    [ app: :net_snmp_ex,
      version: "0.0.11",
      name: "NetSNMP",
      source_url: "https://github.com/jonnystorm/net-snmp-elixir",
      elixir: "~> 1.0",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps,
      docs: [extras: ["README.md"]]
    ]
  end

  defp get_application(:prod) do
    [ applications: [
        :snmp_mib_ex
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
    [ {:snmp_mib_ex, git: "https://github.com/jonnystorm/snmp-mib-elixir"},
      {:ex_doc, "~> 0.13", only: :dev}
    ]
  end
end
