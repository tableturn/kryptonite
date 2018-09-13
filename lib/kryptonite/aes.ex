defmodule Kryptonite.AES do
  alias Kryptonite.Random

  @moduledoc """
  This module allows to easily perform AES related operations, such as generating
  keys, encrypting and decripting.

  ## Examples

  A successful flow of key / iv generation, encryption and decryption can be
  illustrated such as:

      iex> {key, iv} = {generate_key!(), Random.bytes!(16)}
      iex> {:ok, cypher} = encrypt_cbc(key, iv, "Message...")
      iex> decrypt_cbc(key, iv, cypher)
      "Message..."

  In GCM mode, the same flow could be performed like so:

      iex> {key, iv} = {generate_key!(), Random.bytes!(16)}
      iex> ad = "Authentication data used to guard decryption."
      iex> {:ok, cypher, tag} = encrypt_gcm(key, iv, ad, "Message...")
      iex> decrypt_gcm(key, iv, ad, cypher, tag)
      {:ok, "Message..."}

  The advantage of GCM Mode is that it lets you know when the message cannot be
  decrypted properly. In other modes, you just end up with a decrypted garbaged
  message.

      iex> {key, wrong_key, iv} = {generate_key!(), generate_key!(), Random.bytes!(16)}
      iex> ad = "Authentication data used to guard decryption."
      iex> {:ok, cypher, tag} = encrypt_gcm(key, iv, ad, "Message...")
      iex> decrypt_gcm(wrong_key, iv, ad, cypher, tag)
      {:error, :decryption_error}
  """

  @key_byte_size 32

  @typedoc "A key is a 256 bit length bitstring."
  @type key :: <<_::256>>
  @typedoc "Initialization vectors must be at least 128 bits."
  # credo:disable-for-next-line /\.Consistency\./
  @type iv :: <<_::128, _::_*8>>
  @typedoc "A cypher is a binary of any shape."
  @type cypher :: binary
  @typedoc "A cypher tag is a binary of any shape."
  @type tag :: binary
  @typedoc "A padded binary can only be multiple of 128 bits long."
  # credo:disable-for-next-line /\.Consistency\./
  @type padded :: <<_::_*128>>

  @doc """
  Generates an AES key.

  ## Examples

      iex> key = generate_key!()
      iex> bit_size(key)
      256
      iex> generate_key!() == generate_key!()
      false
  """
  @spec generate_key!() :: key | {:error, any}
  def generate_key!, do: Random.bytes!(@key_byte_size)

  @doc """
  Generates an AES key.

  ## Examples

      iex> {:ok, key} = generate_key()
      iex> bit_size(key)
      256
      iex> generate_key() == generate_key()
      false
  """
  @spec generate_key() :: {:ok, key} | {:error, any}
  def generate_key, do: Random.bytes(@key_byte_size)

  @doc """
  Derives an AES key deterministically based on a password.

  ## Examples

      iex> password = "Awesome Passw0rd!"
      iex> opts = [salt: "S", rounds: 2]
      iex> bit_size(derive_key(password, opts))
      256
      iex> derive_key(password, opts) == derive_key(password, opts)
      true
  """
  @spec derive_key(String.t(), keyword) :: key
  def derive_key(password, opts),
    do:
      password
      |> salt(Keyword.fetch!(opts, :salt))
      |> Random.hash_round(Keyword.fetch!(opts, :rounds))
      |> cut_key()

  @doc """
  Encrypt a `msg` with AES in CBC mode.

  Returns a tuple containing the `initialization_vector`, and `cypher`.
  At a high level encryption using AES in CBC mode looks like this:

      key + msg -> iv + cypher

  ## Examples

      iex> {:ok, cypher} = encrypt_cbc(generate_key!(), Random.bytes!(16), "Message...")
      iex> is_bitstring(cypher)
      true
  """
  @spec encrypt_cbc(key, iv, binary) :: {:ok, cypher} | {:error, any}
  def encrypt_cbc(key, iv, msg) do
    {:ok, :crypto.block_encrypt(:aes_cbc256, key, iv, pad(msg))}
  catch
    _, e -> {:error, e}
  end

  @doc """
  Encrypt a `msg` with AES in CBC mode.

  Returns a tuple containing the `initialization_vector`, and `cypher`.
  At a high level encryption using AES in CBC mode looks like this:

      key + iv + ad + msg -> cypher + tag

  ## Examples

      iex> {key, iv} = {generate_key!(), Random.bytes!(16)}
      iex> {:ok, cypher, tag} = encrypt_gcm(key, iv, "Auth", "Message...")
      iex> is_binary(cypher) and is_binary(tag)
      true
  """
  @spec encrypt_gcm(key, iv, binary, binary) :: {:ok, cypher, tag} | {:error, any}
  def encrypt_gcm(key, iv, ad, msg) do
    :aes_gcm
    |> :crypto.block_encrypt(key, iv, {ad, msg})
    |> Tuple.insert_at(0, :ok)
  catch
    _, e -> {:error, e}
  end

  @doc """
  Encrypts a stream using AES in CTR mode.

  ## Examples

      iex> {key, iv} = {generate_key!(), Random.bytes!(16)}
      iex> 'This is a secret'
      ...>     |> stream_encrypt(key, iv)
      ...>     |> Enum.to_list()
      ...>     |> is_list()
      true
  """
  @spec stream_encrypt(Enumerable.t(), key, iv) :: Enumerable.t()
  def stream_encrypt(stream, key, iv) do
    acc0 = :crypto.stream_init(:aes_ctr, key, iv)

    reduce = fn elem, acc ->
      {acc, cypher} = :crypto.stream_encrypt(acc, elem |> List.wrap())
      {[cypher], acc}
    end

    Stream.transform(stream, acc0, reduce)
  end

  @doc """ 
  Encrypts + HMAC a stream into a Collectable

  ## Examples

      iex> {key, iv} = {generate_key!(), Random.bytes!(16)}
      iex> File.write!("/tmp/plain.txt", "This is a secret")
      iex> {:ok, tag} =
      ...>   "/tmp/plain.txt"
      ...>   |> File.stream!()
      ...>   |> stream_encrypt(File.stream!("/tmp/secret.aes"), key, iv, "Auth...")
      iex> {File.rm!("/tmp/plain.txt"), File.rm!("/tmp/secret.aes")}
      iex> is_binary(tag)
      true
  """
  @spec stream_encrypt(Enumerable.t, Collectable.t, key, iv, binary) :: {:ok, tag}
  def stream_encrypt(in_stream, out_stream, key, iv, ad) do
    # :P
    mac_store = spawn_hmac(:sha256, ad)
    aes_ctx =
      :aes_ctr
      |> :crypto.stream_init(key, iv)
    acc0 = %{mac: mac_store, aes: aes_ctx}

    reducer = fn elem, %{mac: mac_store, aes: aes_ctx}=acc ->
      {aes_ctx, cypher} = :crypto.stream_encrypt(aes_ctx, elem |> List.wrap())
      :ok = update_hmac(mac_store, cypher)
      {[cypher], %{acc | aes: aes_ctx}}
    end

    :ok =
      [iv]
      |> Stream.concat(in_stream)
      |> Stream.transform(acc0, reducer)
      |> Stream.into(out_stream)
      |> Stream.run()

    {:ok, get_hmac(mac_store)}
  end

  @doc """
  Decrypts a `cypher` using AES in CBC mode.

  This function must be provided with the same initialization vector `iv` that
  was used to perform the encryption.

  ## Examples

      iex> {key, iv} = {generate_key!(), Random.bytes!(16)}
      iex> msg = "Message..."
      iex> {:ok, cypher} = encrypt_cbc(key, iv, msg)
      iex> msg == decrypt_cbc(key, iv, cypher)
      true
  """
  @spec decrypt_cbc(key, iv, cypher) :: binary
  def decrypt_cbc(key, iv, cypher),
    do:
      :aes_cbc256
      |> :crypto.block_decrypt(key, iv, cypher)
      |> unpad()

  @doc """
  Decrypts a `cypher` using AES in GCM mode.

  ## Examples

      iex> {key, iv} = {generate_key!(), Random.bytes!(16)}
      iex> ad = "Auth data..."
      iex> {:ok, cypher, tag} = encrypt_gcm(key, iv, ad, "Message...")
      iex> decrypt_gcm(key, iv, ad, cypher, tag)
      {:ok, "Message..."}
  """
  @spec decrypt_gcm(key, iv, binary, cypher, tag) :: {:ok, binary} | {:error, any}
  def decrypt_gcm(key, iv, ad, cypher, tag) do
    :aes_gcm
    |> :crypto.block_decrypt(key, iv, {ad, cypher, tag})
    |> case do
      :error -> {:error, :decryption_error}
      msg when is_binary(msg) -> {:ok, msg}
    end
  end

  @doc """
  Decrypts a stream using AES in CTR mode.

  ## Examples

      iex> {key, iv} = {generate_key!(), Random.bytes!(16)}
      iex> msg = "This is a secret..."
      iex> msg == msg
      ...>     |> String.to_charlist()
      ...>     |> stream_encrypt(key, iv)
      ...>     |> Enum.to_list()
      ...>     |> stream_decrypt(key, iv)
      ...>     |> Enum.to_list()
      ...>     |> :erlang.iolist_to_binary
      true
  """
  @spec stream_decrypt(Enumerable.t(), key, iv) :: Enumerable.t()
  def stream_decrypt(stream, key, iv) do
    acc0 = :crypto.stream_init(:aes_ctr, key, iv)

    reduce = fn elem, acc ->
      {acc, cypher} = :crypto.stream_decrypt(acc, elem)
      {[cypher], acc}
    end

    Stream.transform(stream, acc0, reduce)
  end

  # Private stuff.

  @spec pad(binary) :: padded
  defp pad(data) do
    to_add = 16 - rem(byte_size(data), 16)
    data <> to_string(:string.chars(to_add, to_add))
  end

  @spec unpad(padded) :: binary
  defp unpad(data) do
    to_remove = :binary.last(data)
    :binary.part(data, 0, byte_size(data) - to_remove)
  end

  @spec salt(binary, binary) :: binary
  defp salt(stuff, salt), do: stuff <> ":" <> salt

  @spec cut_key(binary) :: binary
  defp cut_key(<<key::binary-size(@key_byte_size), _::binary>>), do: key

  ###
  ### HMAC computer
  ###
  def spawn_hmac(type, key) do
    from = self()
    
    spawn_link(fn ->
      type
      |> :crypto.hmac_init(key)
      |> loop_hmac(from)
    end)
  end

  defp loop_hmac(ctx, from) do
    receive do
      {:update, ^from, data} ->
        ctx
        |> :crypto.hmac_update(data)
        |> loop_hmac(from)

      {:get, ^from} ->
        tag = :crypto.hmac_final(ctx)
        send(from, {:tag, self(), tag})
    end
  end

  def update_hmac(pid, data) do
    _ = send(pid, {:update, self(), data})
    :ok
  end

  def get_hmac(pid) do
    _ = send(pid, {:get, self()})
    receive do
      {:tag, ^pid, tag} -> tag
    end
  end
end
