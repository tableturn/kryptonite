defmodule Kryptonite.Random do
  @moduledoc """
  This module provides helper functions related to generating data at random.
  """

  @doc """
  Returns a string at random where the length is equal to `length`.

  ## Examples

      iex> data = bytes!(16)
      iex> {byte_size(data), bit_size(data)}
      {16, 128}
      iex> data = bytes!(32)
      iex> {byte_size(data), bit_size(data)}
      {32, 256}
  """
  @spec bytes!(integer) :: binary
  def bytes!(length), do: :crypto.strong_rand_bytes(length)

  @doc """
  Returns a string at random where the length is equal to `length`.
  Essentially the same as `bytes!/1` but returns a tuple on error
  instead of raising.

  ## Examples

      iex> data = bytes!(16)
      iex> {byte_size(data), bit_size(data)}
      {16, 128}
      iex> bytes(-1)
      {:error, :badarg}
  """
  @spec bytes(integer) :: {:ok, binary} | {:error, any}
  def bytes(length) do
    {:ok, bytes!(length)}
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

  @doc """
  Calculates the entropy rating of a given binary.

  The Shannon index is calculated by looking at the recurence of values in
  the given `input` binary.

  ## Examples

      iex> shannon_entropy <<0xCaffee, 0xBadF00d,>>
      1.0
      iex> shannon_entropy <<1, 2, 3, 4>>
      2.0
      iex> shannon_entropy "1223334444"
      1.8464393446710154
  """
  @spec shannon_entropy(binary) :: float
  def shannon_entropy(input) do
    len = String.length(input)

    input
    |> String.graphemes()
    |> Enum.group_by(& &1)
    |> Enum.map(fn {_, value} -> length(value) end)
    |> Enum.reduce(0, fn count, entropy ->
      freq = count / len
      entropy - freq * :math.log2(freq)
    end)
  end
end
