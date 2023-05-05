defmodule Kryptonite.AESTest do
  use ExUnit.Case, async: true
  alias Kryptonite.{AES, Random}
  doctest AES, import: true

  @password "Some re4lly secUre stuff!"
  @message "Some simple\ntext message."
  @auth_data "Some random stuff."

  describe "generate_key!/0" do
    test "generate an AES key the right size" do
      assert 256 == bit_size(AES.generate_key!())
    end

    test "is random" do
      refute AES.generate_key!() == AES.generate_key!()
    end
  end

  describe "generate_key/0" do
    test "generate an AES key the right size" do
      {:ok, key} = AES.generate_key()
      assert 256 == bit_size(key)
    end

    test "is random" do
      refute AES.generate_key() == AES.generate_key()
    end
  end

  describe "derive_key/1+1" do
    @opts [salt: "S", rounds: 2]
    test "generates a key given a password" do
      assert 256 ==
               @password
               |> AES.derive_key(@opts)
               |> bit_size()
    end

    test "is deterministic" do
      assert AES.derive_key(@password, @opts) == AES.derive_key(@password, @opts)
    end
  end

  describe "encrypt_ctr/3" do
    setup :key

    test "encrypts properly", %{key: key, iv: iv} do
      {:ok, cypher} = AES.encrypt_ctr(key, iv, @message)
      assert is_bitstring(cypher)
    end
  end

  describe "encrypt_gcm/4" do
    setup :key

    test "encrypts properly", %{key: key, iv: iv} do
      {:ok, cypher, tag} = AES.encrypt_gcm(key, iv, "Auth", "Message...")
      assert is_binary(cypher) and is_binary(tag)
    end
  end

  describe "decrypt_ctr/3" do
    setup :key

    test "decrypts the original message", %{key: key, iv: iv} do
      {:ok, cypher} = AES.encrypt_ctr(key, iv, @message)
      assert @message == AES.decrypt_ctr(key, iv, cypher)
    end
  end

  describe "decrypt_gcm/5" do
    setup :key

    test "decrypts the original message", %{key: key, iv: iv} do
      {:ok, cypher, tag} = AES.encrypt_gcm(key, iv, @auth_data, @message)
      assert {:ok, @message} == AES.decrypt_gcm(key, iv, @auth_data, cypher, tag)
    end

    test "returns an error tuple upon failure", %{key: key, iv: iv} do
      assert match?(
               {:error, :decryption_error},
               AES.decrypt_gcm(key, iv, @auth_data, "bad cypher", "bad tag")
             )
    end
  end

  defp key(_) do
    key = AES.generate_key!()
    {:ok, key: key, iv: Random.bytes!(16)}
  end
end
