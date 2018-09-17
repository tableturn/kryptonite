defmodule Kryptonite.AESTest do
  use ExUnit.Case, async: true
  alias Kryptonite.{AES, AES.StreamIntegrityError, Random}
  doctest AES, import: true

  @password "Some re4lly secUre stuff!"
  @message "Some simple\ntext message."
  @auth_data "Some random stuff."

  describe ".generate_key!/0" do
    test "generate an AES key the right size" do
      assert 256 == bit_size(AES.generate_key!())
    end

    test "is random" do
      refute AES.generate_key!() == AES.generate_key!()
    end
  end

  describe ".generate_key/0" do
    test "generate an AES key the right size" do
      {:ok, key} = AES.generate_key()
      assert 256 == bit_size(key)
    end

    test "is random" do
      refute AES.generate_key() == AES.generate_key()
    end
  end

  describe ".derive_key/1+1" do
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

  describe ".encrypt_cbc/3" do
    setup :key

    test "encrypts properly", %{key: key, iv: iv} do
      {:ok, cypher} = AES.encrypt_cbc(key, iv, @message)
      assert is_bitstring(cypher)
    end
  end

  describe ".encrypt_gcm/4" do
    setup :key

    test "encrypts properly", %{key: key, iv: iv} do
      {:ok, cypher, tag} = AES.encrypt_gcm(key, iv, "Auth", "Message...")
      assert is_binary(cypher) and is_binary(tag)
    end
  end

  describe ".stream_encrypt/3" do
    setup :key

    test "outputs a stream list", %{key: key, iv: iv} do
      assert 'This is a secret'
             |> AES.stream_encrypt(key, iv)
             |> Enum.to_list()
             |> is_list()
    end
  end

  describe ".stream_encrypt/5" do
    setup :key

    test "encrypts files", %{key: key, iv: iv} do
      fid = :rand.uniform(1_000_000)
      {plain, enc} = {"/tmp/#{fid}.txt", "/tmp/#{fid}.aes"}
      File.write!(plain, @message)

      {:ok, tag} =
        plain
        |> File.stream!()
        |> AES.stream_encrypt(File.stream!(enc), key, iv, @auth_data)

      Enum.each([plain, enc], &File.rm!/1)
      assert is_binary(tag)
    end
  end

  describe ".stream_decrypt/5" do
    setup :key

    test "decrypts the original message", %{key: key, iv: iv} do
      fid = :rand.uniform(1_000_000)
      {plain, enc} = {"/tmp/#{fid}.txt", "/tmp/#{fid}.aes"}
      File.write!(plain, @message)

      {:ok, tag} =
        plain
        |> File.stream!()
        |> AES.stream_encrypt(File.stream!(enc), key, iv, @auth_data)

      assert @message ==
               enc
               |> File.stream!()
               |> AES.stream_decrypt!(key, iv, @auth_data, tag)
               |> Enum.to_list()
               |> IO.iodata_to_binary()
    end

    test "raises when the stream is corrupted", %{key: key, iv: iv} do
      fid = :rand.uniform(1_000_000)
      enc = "/tmp/#{fid}.aes"
      File.write!(enc, "incorrect data")
      tag = <<0::size(128)>>

      assert_raise StreamIntegrityError, fn ->
        enc
        |> File.stream!()
        |> AES.stream_decrypt!(key, iv, @auth_data, tag)
      end
    end
  end

  describe ".decrypt_cbc/3" do
    setup :key

    test "decrypts the original message", %{key: key, iv: iv} do
      {:ok, cypher} = AES.encrypt_cbc(key, iv, @message)
      assert @message == AES.decrypt_cbc(key, iv, cypher)
    end
  end

  describe ".decrypt_gcm/5" do
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

  describe "stream_decrypt!/3" do
    setup :key

    test "decrypts a stream", %{key: key, iv: iv} do
      cypher =
        @message
        |> String.to_charlist()
        |> AES.stream_encrypt(key, iv)
        |> Enum.to_list()

      assert @message ==
               cypher
               |> AES.stream_decrypt(key, iv)
               |> Enum.to_list()
               |> :erlang.iolist_to_binary()
    end
  end

  defp key(_) do
    key = AES.generate_key!()
    {:ok, key: key, iv: Random.bytes!(16)}
  end
end
