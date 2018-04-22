defmodule Kryptonite.Bip39 do
  @moduledoc """
  This module allows for easy transformation between a binary and a mnemonic phrase.

  Its main limitation is the fact that the data **must** have a **byte size** that
  is a multiple of 4 and comprised between 4 and 1024.
  """

  @me __MODULE__
  @words Kryptonite.Wordlist.all()

  @type t :: %__MODULE__{words: String.t(), data: binary, checksum: bitstring}
  defstruct words: nil, data: nil, checksum: nil

  @doc """
  Generates random entropy of the given `size_in_bytes` and its associated wording.
  Note that the specified size *must* be a multiple of four.

  Returns a `t()` or `{:error, atom}`.

  ## Examples

      iex> %Kryptonite.Bip39{data: data, words: words} = generate(4)
      iex> byte_size(data) == 4 && bit_size(data) == 32
      true
      iex> String.length(words) != 0
      true

      iex> generate(3)
      {:error, :invalid_data_size}
      iex> generate(11)
      {:error, :invalid_data_size}
  """
  @spec generate(pos_integer) :: t | {:error, atom}
  def generate(size_in_bytes) do
    with true <- ensure_valid_data_size(size_in_bytes) do
      size_in_bytes
      |> :crypto.strong_rand_bytes()
      |> from_data()
    end
  end

  @doc """
  Builds a Bip39 structure given some `data`. Note that the data length *must*
  follow the same rules as for `generate/1`.

  Returns a `t()` or `{:error, atom}`.

  ### Examples

      iex> seed = "Hey."
      iex> %Kryptonite.Bip39{data: data} = from_data(seed)
      iex> seed == data
      true

      iex> from_data(<<0, 0, 0, 0>>).words
      "abandon abandon ability"
      iex> from_data(<<255, 255, 255, 255, 255, 255, 255, 255>>).words
      "zoo zoo zoo zoo zoo zebra"

      iex> from_data(<<1, 2, 3>>)
      {:error, :invalid_data_size}
      iex> from_data(<<1, 2, 3, 4, 5>>)
      {:error, :invalid_data_size}
  """
  @spec from_data(binary) :: t | {:error, atom}
  def from_data(data) do
    with true <- ensure_valid_data_size(byte_size(data)) do
      checksum = compute_checksum(data)
      %@me{data: data, checksum: checksum, words: to_words(data, checksum)}
    end
  end

  @doc """
  Builds a Bip39 structure given a wordlist. Each word is verified to exist and
  the checksum is verified against the rebuilt data.

  Returns `t()` or `{:error, atom}`.

  ## Examples

      iex> seed = "abandon abandon ability"
      iex> %Kryptonite.Bip39{words: words, data: data} = from_words(seed)
      iex> seed == words && data == <<0, 0, 0, 0>>
      true

      iex> seed = "zoo zoo zoo zoo zoo zebra"
      iex> from_words(seed).data
      <<255, 255, 255, 255, 255, 255, 255, 255>>

      iex> from_words("foobar")
      {:error, :invalid_word}

      iex> from_words("random word nothing work")
      {:error, :invalid_checksum}
  """
  @spec from_words(String.t()) :: t | {:error, atom}
  def from_words(words) do
    with {:ok, {data, checksum}} <- to_data(words),
         true <- ensure_matching_checksum(data, checksum) do
      %@me{words: words, data: data, checksum: checksum}
    end
  end

  # Private stuff.

  @spec to_words(binary, bitstring) :: String.t() | {:error, :invalid_word | :invalid_checksum}
  defp to_words(data, checksum) do
    for <<(index::11 <- <<data::bits, checksum::bits>>)>> do
      Enum.at(@words, index)
    end
    |> Enum.join(" ")
  end

  @spec to_data(String.t()) :: {:ok, {binary, bitstring}} | {:error, :invalid_word}
  defp to_data(words) do
    bits =
      words
      |> String.split()
      |> Enum.reduce_while({:ok, <<>>}, &accumulate_word_bits/2)

    with {:ok, bits} <- bits do
      len = bit_size(bits)
      checksum_size = div(len - div(len, 33), 32)
      data_size = div(len - checksum_size, 8)
      <<data::binary-size(data_size), checksum::bits>> = bits
      {:ok, {data, checksum}}
    end
  end

  @spec accumulate_word_bits(String.t(), {:ok, bitstring}) ::
          {:cont, {:ok, bitstring}} | {:halt, {:error, :invalid_word}}
  defp accumulate_word_bits(word, {:ok, acc}) do
    @words
    |> Enum.find_index(&(&1 == word))
    |> case do
      nil -> {:halt, {:error, :invalid_word}}
      index -> {:cont, {:ok, <<acc::bits, (<<index::size(11)>>)>>}}
    end
  end

  @spec ensure_valid_data_size(pos_integer) :: boolean | {:error, :invalid_data_size}
  defp ensure_valid_data_size(size) do
    (size >= 4 && size <= 1024 && rem(size, 4) == 0) || {:error, :invalid_data_size}
  end

  @spec ensure_matching_checksum(binary, bitstring) :: true | {:error, :invalid_checksum}
  def ensure_matching_checksum(data, checksum) do
    checksum == compute_checksum(data) || {:error, :invalid_checksum}
  end

  @spec compute_checksum(binary) :: bitstring
  defp compute_checksum(data) do
    size = div(bit_size(data), 32)
    <<checksum::bits-size(size), _::bits>> = :crypto.hash(:sha256, data)
    checksum
  end
end
