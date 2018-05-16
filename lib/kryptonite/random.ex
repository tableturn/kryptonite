defmodule Kryptonite.Random do
  @moduledoc """
  This module provides helper functions related to generating data at random.
  """

  @doc """
  Returns a string at random where the length is equal to `length`.

  ## Examples

      iex> {:ok, data} = bytes(16)
      iex> {byte_size(data), bit_size(data)}
      {16, 128}
      iex> {:ok, data} = bytes(32)
      iex> {byte_size(data), bit_size(data)}
      {32, 256}
      iex> bytes(-1)
      {:error, :badarg}
  """
  @spec bytes(integer) :: {:ok, binary} | {:error, any}
  def bytes(length) do
    {:ok, :crypto.strong_rand_bytes(length)}
  catch
    _, e -> {:error, e}
  end

  @doc """
  Hashes a given `digest` over itself for as many times as specified by `count`.

  ## Examples

      iex> m = "Some message."
      iex> hash_round(m, 1) == hash_round(m, 2)
      false
      iex> hash_round(m, 2) == m |> hash_round(1) |> hash_round(1)
      true
  """
  @spec hash_round(binary, pos_integer) :: <<_::512>>
  def hash_round(digest, count) when count > 0,
    do:
      :sha512
      |> :crypto.hash(digest)
      |> hash_round(count - 1)

  def hash_round(digest, _), do: digest
end
