defmodule Kryptonite.RSA.PublicKeyTest do
  use ExUnit.Case, async: true
  alias Kryptonite.RSA.{PrivateKey, PublicKey}
  doctest PublicKey, import: true

  @bad_key {:bad_key}
  @message "Some simple\ntext message."

  setup_all [:key, :cypher]

  describe ".from_native/1" do
    test "builds a key when successful" do
      assert {:ok, %PublicKey{public_modulus: 1, public_exponent: 2}} ==
               PublicKey.from_native({:RSAPublicKey, 1, 2})
    end

    test "errors when given invalid input" do
      assert {:error, :invalid_native} == PublicKey.from_native(@bad_key)
    end
  end

  describe ".to_native/1" do
    test "builds a native key when successful" do
      key = %PublicKey{public_modulus: 2, public_exponent: 3}
      assert {:ok, {:RSAPublicKey, 2, 3}} == PublicKey.to_native(key)
    end

    test "errors when given invalid input" do
      assert {:error, :invalid_public_key} == PublicKey.to_native(@bad_key)
    end
  end

  describe ".verify/3" do
    test "returns true when valid", %{priv: priv, pub: pub} do
      {:ok, signature} = PrivateKey.sign(priv, @message)
      assert true == PublicKey.verify(pub, @message, signature)
    end

    test "errors when given an invalid key" do
      assert {:error, :invalid_public_key} == PublicKey.verify(@bad_key, @message, @message)
    end
  end

  describe ".encrypt/2" do
    test "produces an encrypted cypher when successful", %{pub: pub} do
      {:ok, cypher} = PublicKey.encrypt(pub, @message)
      assert is_binary(cypher)
      refute @message == cypher
    end

    test "errors when given an invalid key" do
      assert {:error, :invalid_public_key} == PublicKey.encrypt(@bad_key, @message)
    end
  end

  describe ".decrypt/2" do
    test "decrypts the message back when successful", %{pub: pub, cypher: cypher} do
      {:ok, message} = PublicKey.decrypt(pub, cypher)
      assert @message == message
    end

    test "errors when given an invalid key", %{cypher: cypher} do
      assert {:error, :invalid_public_key} == PublicKey.decrypt(@bad_key, cypher)
    end

    test "errors when the key doesn't match", %{cypher: cypher} do
      pub = %PublicKey{public_modulus: 3, public_exponent: 5}
      assert {:error, {:decryption_failure, {:error, {'pkey.c', 1184}, 'Couldn\'t get the result'}}}== PublicKey.decrypt(pub, cypher)
    end
  end

  defp key(_) do
    {:ok, priv} = PrivateKey.new(512)
    {:ok, pub} = PrivateKey.public_key(priv)
    {:ok, priv: priv, pub: pub}
  end

  defp cypher(%{priv: priv}) do
    {:ok, cypher} = PrivateKey.encrypt(priv, @message)
    {:ok, cypher: cypher}
  end
end
