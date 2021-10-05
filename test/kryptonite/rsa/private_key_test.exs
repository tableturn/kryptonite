defmodule Kryptonite.RSA.PrivateKeyTest do
  use ExUnit.Case, async: true
  alias Kryptonite.RSA.{PrivateKey, PublicKey}
  doctest PrivateKey, import: true

  @bad_key {:bad_key}
  @message "Some simple\ntext message."

  setup_all [:key, :cypher]

  describe ".new/2" do
    test "generates a key" do
      assert {:ok, %PrivateKey{}} = PrivateKey.new()
    end

    test "errors when given an invalid size" do
      assert {:error, :invalid_key_size} == PrivateKey.new(255)
    end

    test "errors when given an invalid public exponent" do
      assert {:error, :invalid_public_exponent} == PrivateKey.new(512, 1)
    end
  end

  describe ".from_native/1" do
    test "builds a key when successful" do
      {:RSAPrivateKey, v, pm, pe, pv, pm1, pm2, e1, e2, ctrc, opi} =
        native = :public_key.generate_key({:rsa, 512, 65_537})

      assert {:ok,
              %PrivateKey{
                version: v,
                public_modulus: pm,
                public_exponent: pe,
                private_exponent: pv,
                prime_one: pm1,
                prime_two: pm2,
                exponent_one: e1,
                exponent_two: e2,
                ctr_coefficient: ctrc,
                other_prime_infos: opi
              }} == PrivateKey.from_native(native)
    end

    test "errors when given invalid input" do
      assert {:error, :invalid_native} == PrivateKey.from_native(@bad_key)
    end
  end

  describe ".to_native/1" do
    test "builds a native key when successful" do
      key = %PrivateKey{
        version: :"two-prime",
        public_modulus: 2,
        public_exponent: 3,
        private_exponent: 4,
        prime_one: 5,
        prime_two: 6,
        exponent_one: 7,
        exponent_two: 8,
        ctr_coefficient: 9,
        other_prime_infos: 10
      }

      assert {:ok, {:RSAPrivateKey, :"two-prime", 2, 3, 4, 5, 6, 7, 8, 9, 10}} ==
               PrivateKey.to_native(key)
    end

    test "only handles known versions" do
      key = %PrivateKey{version: :bad}
      assert {:error, :invalid_native_version} == PrivateKey.to_native(key)
    end

    test "errors when given invalid input" do
      assert {:error, :invalid_private_key} == PrivateKey.to_native(@bad_key)
    end
  end

  describe ".public_key/1" do
    test "extracts the public components when successful" do
      {:ok, %{public_modulus: pm, public_exponent: pe} = key} = PrivateKey.new(512)
      assert {:ok, %{public_modulus: ^pm, public_exponent: ^pe}} = PrivateKey.public_key(key)
    end

    test "only hanndles known versions" do
      key = %PrivateKey{version: :bad}
      assert {:error, :invalid_native_version} == PrivateKey.public_key(key)
    end

    test "errors when given invalid input" do
      assert {:error, :invalid_private_key} == PrivateKey.public_key(@bad_key)
    end
  end

  describe ".sign/2" do
    test "produces a signature when valid", %{priv: priv} do
      {:ok, signature} = PrivateKey.sign(priv, @message)
      assert is_binary(signature)
      refute @message == signature
    end

    test "errors when given an invalid key" do
      assert {:error, :invalid_private_key} == PrivateKey.encrypt(@bad_key, @message)
    end
  end

  describe ".encrypt/2" do
    test "produces an encrypted cypher when successful", %{priv: priv} do
      {:ok, cypher} = PrivateKey.encrypt(priv, @message)
      assert is_binary(cypher)
      refute @message == cypher
    end

    test "errors when given an invalid key" do
      assert {:error, :invalid_private_key} == PrivateKey.encrypt(@bad_key, @message)
    end
  end

  describe ".decrypt/2" do
    test "decrypts the message back when successful", %{priv: priv, cypher: cypher} do
      {:ok, message} = PrivateKey.decrypt(priv, cypher)
      assert @message == message
    end

    test "errors when given an invalid key", %{cypher: cypher} do
      assert {:error, :invalid_private_key} == PrivateKey.decrypt(@bad_key, cypher)
    end

    test "errors when the key doesn't match", %{cypher: cypher} do
      {:ok, key} = PrivateKey.new(512)
      assert {:error, {:decryption_failure, :decrypt_failed}} == PrivateKey.decrypt(key, cypher)
    end
  end

  defp key(_) do
    {:ok, priv} = PrivateKey.new(512)
    {:ok, pub} = PrivateKey.public_key(priv)
    {:ok, priv: priv, pub: pub}
  end

  defp cypher(%{pub: pub}) do
    {:ok, cypher} = PublicKey.encrypt(pub, @message)
    {:ok, cypher: cypher}
  end
end
