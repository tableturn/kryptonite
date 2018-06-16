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
  def derive_key(password, opts) do
    <<key::binary-size(@key_byte_size), _::binary>> =
      password
      |> salt(Keyword.fetch!(opts, :salt))
      |> Random.hash_round(Keyword.fetch!(opts, :rounds))

    key
  end

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
end
