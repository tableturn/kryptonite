defmodule Kryptonite.RSATest do
  use ExUnit.Case, async: true
  alias Kryptonite.RSA
  alias Kryptonite.RSA.{PrivateKey, PublicKey}
  doctest RSA, import: true

  @bad_key {:bad_key}
  @message "Some simple\ntext message."

  setup_all [:keys, :cypher]

  describe ".new_keypair/2" do
    test "generates a keypair" do
      assert {:ok, %PrivateKey{}, %PublicKey{}} = RSA.new_keypair()
    end

    test "errors when given an invalid public exponent" do
      assert {:error, {:key_generation_error, :badarg}} == RSA.new_keypair(512, 1)
    end
  end

  describe ".authenticated_encrypt/3" do
    test "generates a signed cypher when successful", %{priv1: priv1, pub2: pub2} do
      {:ok, cypher} = RSA.authenticated_encrypt(pub2, priv1, @message)
      assert is_binary(cypher)
    end

    test "errors when encryption key is invalid", %{priv1: priv1} do
      assert {:error, :invalid_public_key} == RSA.authenticated_encrypt(@bad_key, priv1, @message)
    end

    test "errors when signing key is invalid", %{pub2: pub2} do
      assert {:error, :invalid_private_key} == RSA.authenticated_encrypt(pub2, @bad_key, @message)
    end
  end

  describe ".authenticated_decrypt/3" do
    test "can revert to the original", %{priv2: priv2, pub1: pub1, cypher: cypher} do
      {:ok, message} = RSA.authenticated_decrypt(priv2, pub1, cypher)
      assert @message == message
    end

    test "errors when decryption key is invalid", %{pub1: pub1, cypher: cypher} do
      assert {:error, :invalid_private_key} == RSA.authenticated_decrypt(@bad_key, pub1, cypher)
    end

    test "errors when verification key is invalid", %{priv2: priv2, cypher: cypher} do
      assert {:error, :invalid_public_key} == RSA.authenticated_decrypt(priv2, @bad_key, cypher)
    end

    test "errors when signature doesn't match", %{priv2: priv2, pub2: pub2, cypher: cypher} do
      assert {:error, :invalid_signature} == RSA.authenticated_decrypt(priv2, pub2, cypher)
    end

    test "errors when encryption cannot be performed", %{priv1: priv1, pub1: pub1, cypher: cypher} do
      assert {:error, {:decryption_failure, :decrypt_failed}} ==
               RSA.authenticated_decrypt(priv1, pub1, cypher)
    end
  end

  defp keys(_) do
    {:ok, priv1, pub1} = RSA.new_keypair(512)
    {:ok, priv2, pub2} = RSA.new_keypair(512)
    {:ok, priv1: priv1, pub1: pub1, priv2: priv2, pub2: pub2}
  end

  defp cypher(%{priv1: priv1, pub2: pub2}) do
    {:ok, cypher} = RSA.authenticated_encrypt(pub2, priv1, @message)
    {:ok, cypher: cypher}
  end
end
