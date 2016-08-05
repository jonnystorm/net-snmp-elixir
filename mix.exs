defmodule NetSNMP.Mixfile do
  use Mix.Project

  def project do
    [ app: :net_snmp_ex,
      version: "0.0.18",
      name: "NetSNMP",
      source_url: "https://github.com/jonnystorm/net-snmp-elixir",
      elixir: "~> 1.0",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps,
      docs: [extras: ["README.md"]]
    ]
  end

  defp get_env(_) do
    [ field_delimiter: "||",
      max_repetitions: 10
    ]
  end

  defp get_application(_) do
    [ applications: [
        :logger,
        :snmp_mib_ex
      ],
      env: get_env(Mix.env)
    ]
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
