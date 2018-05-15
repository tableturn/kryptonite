defmodule Kryptonite.AES do
  @moduledoc """
  This module allows to easily perform AES related operations, such as generating
  keys, encrypting and decripting.

  ## Examples

  A successful flow of key / iv generation, encryption and decryption can be
  illustrated such as:

      iex> {:ok, key} = generate_aes_key()
      iex> {:ok, iv} = Kryptonite.Random.bytes(16)
      iex> {:ok, cypher} = encrypt_cbc(key, iv, "Message...")
      iex> decrypt_cbc(key, iv, cypher)
      {:ok, "Message..."}
  """

  alias Kryptonite.Random

  @type key :: binary
  @type iv :: binary
  @type message :: binary
  @type auth_data :: binary
  @type cypher :: binary
  @type tag :: binary

  @doc """
  Generates an AES key.

  The key will be formed using a random string of `length_in_bits` bits, and this
  parameter *must* be set to `256` to ensure compatibility
  with the underlying AES functions.

  ## Examples

      iex> {:ok, key} = generate_aes_key()
      iex> bit_size(key)
      256
      iex> generate_aes_key() != generate_aes_key()
      true
  """
  @spec generate_aes_key() :: {:ok, key}
  def generate_aes_key(), do: Random.bytes(32)

  @doc """
  Encrypt a `msg` with AES in CBC mode.

  Returns a tuple containing the `initialization_vector`, and `cypher`.
  At a high level encryption using AES in CBC mode looks like this:

      key + msg -> iv + cypher

  ## Examples

      iex> {{:ok, key}, {:ok, iv}} = {generate_aes_key(), Kryptonite.Random.bytes(16)}
      iex> {:ok, cypher} = encrypt_cbc(key, iv, "Message...")
      iex> is_bitstring(cypher)
      true
  """
  @spec encrypt_cbc(key, iv, message) :: {:ok, cypher} | {:error, any}
  def encrypt_cbc(key, iv, msg) do
    cypher = :crypto.block_encrypt(:aes_cbc256, key, iv, pad(msg))
    {:ok, cypher}
  catch
    _, e -> {:error, e}
  end

  @doc """
  Encrypt a `msg` with AES in CBC mode.

  Returns a tuple containing the `initialization_vector`, and `cypher`.
  At a high level encryption using AES in CBC mode looks like this:

      key + iv + ad + msg -> cypher + tag

  ## Examples

      iex> {{:ok, key}, {:ok, iv}} = {generate_aes_key(), Kryptonite.Random.bytes(16)}
      iex> {:ok, cypher, tag} = encrypt_gcm(key, iv, "Auth", "Message...")
      iex> is_binary(cypher) and is_binary(tag)
      true
  """
  @spec encrypt_gcm(key, iv, auth_data, message) :: {:ok, cypher, tag} | {:error, any}
  def encrypt_gcm(key, iv, ad, msg) do
    {cypher, tag} = :crypto.block_encrypt(:aes_gcm, key, iv, {ad, msg})
    {:ok, cypher, tag}
  catch
    _, e -> {:error, e}
  end

  @doc """
  Decrypts a `cypher` using AES in CBC mode.

  This function must be provided with the same initialization vector `iv` that
  was used to perform the encryption.

  ## Examples

      iex> {{:ok, key}, {:ok, iv}} = {generate_aes_key(), Kryptonite.Random.bytes(16)}
      iex> msg = "Message..."
      iex> {:ok, cypher} = encrypt_cbc(key, iv, msg)
      iex> {:ok, msg} == decrypt_cbc(key, iv, cypher)
      true
  """
  @spec decrypt_cbc(key, iv, cypher) :: {:ok, message} | {:error, any}
  def decrypt_cbc(key, iv, cypher) do
    :aes_cbc256
    |> :crypto.block_decrypt(key, iv, cypher)
    |> unpad
    |> Tuple.duplicate(1)
    |> Tuple.insert_at(0, :ok)
  end

  @doc """
  Decrypts a `cypher` using AES in GCM mode.

  ## Examples

      iex> {{:ok, key}, {:ok, iv}} = {generate_aes_key(), Kryptonite.Random.bytes(16)}
      iex> ad = "Auth data..."
      iex> {:ok, cypher, tag} = encrypt_gcm(key, iv, ad, "Message...")
      iex> decrypt_gcm(key, iv, ad, cypher, tag)
      {:ok, "Message..."}
  """
  @spec decrypt_gcm(key, iv, auth_data, cypher, tag) :: {:ok, message} | {:error, any}
  def decrypt_gcm(key, iv, ad, cypher, tag) do
    :aes_gcm
    |> :crypto.block_decrypt(key, iv, {ad, cypher, tag})
    |> case do
      :error -> {:error, :decryption_error}
      msg when is_binary(msg) -> {:ok, msg}
    end
  end

  # Private stuff.

  @spec pad(binary) :: binary
  defp pad(data) do
    to_add = 16 - rem(byte_size(data), 16)
    data <> to_string(:string.chars(to_add, to_add))
  end

  @spec unpad(binary) :: binary
  defp unpad(data) do
    to_remove = :binary.last(data)
    :binary.part(data, 0, byte_size(data) - to_remove)
  end
end
