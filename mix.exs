defmodule Kryptonite.MixProject do
  use Mix.Project

  def project do
    [
      app: :kryptonite,
      version: "0.1.1",
      elixir: "~> 1.4",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Kryptonite",
      source_url: "https://github.com/the-missing-link/kryptonite",
      homepage_url: "https://github.com/the-missing-link/kryptonite",
      docs: [extras: ~w(README.md)],
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: cli_env_for(:test, ~w(
        coveralls coveralls.detail coveralls.html coveralls.json coveralls.post
        vcr.delete vcr.check vcr.show
      )),
      package: package(),
      description: """
        A kollektion of skripts that probably are very klose to cryptography
        but aren't - hence the typo.
      """
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Dev only.
      {:mix_test_watch, "~> 0.5", only: :dev, runtime: false},
      {:credo, "~> 0.8", only: :dev, runtime: false},
      {:dialyxir, "~> 0.5", only: :dev, runtime: false},
      {:ex_doc, "~> 0.16", only: :dev, runtime: false},
      {:excoveralls, "~> 0.8", only: :test, runtime: false}
    ]
  end

  defp cli_env_for(env, tasks) do
    Enum.reduce(tasks, [], &Keyword.put(&2, :"#{&1}", env))
  end

  defp package do
    [
      name: "kryptonite",
      files: ["lib", "mix.exs", "README*"],
      maintainers: ["Pierre Martin"],
      licenses: ["Apache 2.0"],
      links: %{"GitHub" => "https://github.com/the-missing-link/kryptonite"}
    ]
  end
end
