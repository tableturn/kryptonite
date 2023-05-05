defmodule Kryptonite.MixProject do
  use Mix.Project

  def project do
    [
      app: :kryptonite,
      version: "1.0.0",
      elixir: "~> 1.14.1",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Kryptonite",
      source_url: "https://github.com/tableturn/kryptonite",
      homepage_url: "https://github.com/tableturn/kryptonite",
      dialyzer: [plt_add_deps: :project, plt_add_apps: [:public_key]],
      docs: [extras: ~w(README.md)],
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: cli_env_for(:test, ~w(
        coveralls coveralls.detail coveralls.html coveralls.json coveralls.post
      )),
      package: package(),
      description:
        "A collection of modules that are very close to cryptography but aren't - hence the typo.",
      aliases: aliases(),

    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Dev and Test only.
      {:credo, "~> 1.7.0", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.3.0", only: [:dev, :test], runtime: false},
      # Dev only.
      {:ex_doc, "~> 0.29.4", only: :dev, runtime: false},
      {:excoveralls, "~> 0.16.1", only: :test, runtime: false}
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
      links: %{"GitHub" => "https://github.com/tableturn/kryptonite"}
    ]
  end

  def aliases() do
    [
     "dev.update_deps": [
       "hex.outdated --within-requirements",
       "deps.update --all --only",
       "deps.clean --all --only",
       "deps.get",
       "deps.compile",
       "hex.outdated --within-requirements"
     ]
   ]
 end
end
