# Kryptonite

[![Build Status](https://ci.emage.run/api/badges/the-missing-link/kryptonite/status.svg)](https://ci.emage.run/the-missing-link/kryptonite)
[![Coverage Report](https://codecov.io/gh/the-missing-link/kryptonite/branch/master/graph/badge.svg?token=xsuechvNxp)](https://codecov.io/gh/the-missing-link/kryptonite)
[![Hex.pm](https://img.shields.io/hexpm/dt/kryptonite.svg)](https://hex.pm/packages/kryptonite)

A collection of modules that are very close to cryptography but aren't - hence the typo.

## Motivations

We initially were using the excellent [`ExCrypto`](https://github.com/ntrepid8/ex_crypto).
For all intent and purposes, that's what you should be using. However, we quickly realized
that [`ExCrypto`](https://github.com/ntrepid8/ex_crypto) is:

- Performing superfluous operations (Base64 encoding, computing key fingerprints, etc).
- Offering outdated options (AES `:notsup` key lengths).
- Not offering some of the functions we needed (Mnemonics etc).

This is why we decided to roll our own. We also are aiming for an evergreen coverage
and typespec.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `kryptonite` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:kryptonite, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/kryptonite](https://hexdocs.pm/kryptonite).
