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
end
