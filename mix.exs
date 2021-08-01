defmodule GCSSign.MixProject do
  use Mix.Project

  @version "1.0.1"
  @repo_url "https://github.com/jeroenvisser101/gcs_sign"

  def project do
    [
      app: :gcs_sign,
      version: @version,
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      dialyzer: dialyzer(),

      # Hex
      package: package(),
      description: "A tiny package for signing Google Cloud Storage URLs and forms",

      # Docs
      name: "GCSSign",
      docs: docs()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [extra_applications: [:logger, :public_key]]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jason, "~> 1.2"},
      {:ex_doc, ">= 0.19.0", only: :dev},
      {:dialyxir, "~> 1.1", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["Jeroen Visser"],
      licenses: ["MIT"],
      links: %{"GitHub" => @repo_url}
    ]
  end

  defp docs do
    [
      main: "GCSSign",
      source_ref: "v#{@version}",
      source_url: @repo_url
    ]
  end

  defp dialyzer do
    [
      plt_file:
        {:no_warn, ".dialyzer/elixir-#{System.version()}-erlang-otp-#{System.otp_release()}.plt"}
    ]
  end
end
