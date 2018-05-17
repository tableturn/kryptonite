defmodule KryptoniteTest do
  use ExUnit.Case, async: true
  alias Kryptonite.{AES, Bip39, Random, Wordlist}
  doctest Kryptonite, import: true
  doctest AES, import: true
  doctest Bip39, import: true
  doctest Random, import: true
  doctest Wordlist, import: true

  @password "Strong P4ssw0rd!~"
  @words "flee chat speed area sort inspire middle problem three hire present noodle " <>
           "frame smooth bubble turtle spot thrive blanket outer language rather salmon latin"

  describe "integration" do
    test "can convert from a password to an AES key to a mnemonic" do
      %{words: words} =
        @password
        |> AES.derive_key()
        |> Bip39.from_data()

      assert @words == words
    end

    test "can convert from a mnemonic to an AES key" do
      %{data: key} = Bip39.from_words(@words)
      assert AES.derive_key(@password) == key
    end
  end
end
