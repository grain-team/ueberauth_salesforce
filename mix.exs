defmodule UeberauthSalesforce.Mixfile do
  use Mix.Project

  @source_url "https://github.com/grain-team/ueberauth_salesforce"
  @version "0.1.0"

  def project do
    [
      app: :ueberauth_salesforce,
      version: @version,
      name: "Üeberauth Salesforce",
      elixir: "~> 1.8",
      start_permanent: Mix.env() == :prod,
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :oauth2, :ueberauth]
    ]
  end

  defp deps do
    [
      {:oauth2, "~> 1.0 or ~> 2.0"},
      {:ueberauth, "~> 0.7"},
      {:credo, ">= 0.0.0", only: [:dev], runtime: false},
      {:ex_doc, ">= 0.0.0", only: [:dev], runtime: false}
    ]
  end

  defp docs do
    [
      extras: ["README.md"],
      main: "readme",
      source_url: @source_url,
      homepage_url: @source_url,
      formatters: ["html"]
    ]
  end

  defp package do
    [
      description: "An Uberauth strategy for Salesforce authentication.",
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["Grain"],
      licenses: ["MIT"],
      links: %{
        GitHub: @source_url
      }
    ]
  end
end
