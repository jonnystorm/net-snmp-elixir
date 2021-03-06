defmodule NetSNMP.Mixfile do
  use Mix.Project

  def project do
    [ app: :net_snmp_ex,
      version: "0.1.1",
      name: "NetSNMP",
      source_url: "https://gitlab.com/jonnystorm/net-snmp-elixir",
      elixir: "~> 1.4",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps(),
      docs: [extras: ["README.md"]],
      dialyzer: [
        add_plt_apps: [
          :logger,
          :snmp_mib_ex,
        ],
        ignore_warnings: "dialyzer.ignore",
        flags: [
          :unmatched_returns,
          :error_handling,
          :race_conditions,
          :underspecs,
        ],
      ],
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
    [ {:snmp_mib_ex, git: "https://gitlab.com/jonnystorm/snmp-mib-elixir.git"},
      {:ex_doc, "~> 0.15", only: :dev}
    ]
  end
end
