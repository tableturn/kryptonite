defmodule Kryptonite.RSA do
  alias Kryptonite.RSA.{PrivateKey, PublicKey}

  @type message :: binary
  @type cypher :: binary
  @type signature :: binary
  @type signed_cypher :: binary
  @type priv :: PrivateKey.t()
  @type pub :: PublicKey.t()

  @spec new_keypair(pos_integer, pos_integer) :: {:ok, priv, pub} | {:error, any}
  def new_keypair(size_in_bits \\ 2048, public_exponent \\ 65_537) do
    with {:ok, priv} <- PrivateKey.new(size_in_bits, public_exponent),
         {:ok, pub} <- PrivateKey.public_key(priv) do
      {:ok, priv, pub}
    end
  end

  @spec authenticated_encrypt(pub, priv, message) :: {:ok, signed_cypher} | {:error, any}
  def authenticated_encrypt(enc_pub_key, sig_priv_key, msg) do
    with {:ok, cypher} <- PublicKey.encrypt(enc_pub_key, msg),
         {:ok, sig} <- PrivateKey.sign(sig_priv_key, cypher) do
      serialize({sig, cypher})
    end
  end

  @spec authenticated_decrypt(priv, pub, signed_cypher) :: {:ok, message} | {:error, any}
  def authenticated_decrypt(dec_priv_key, ver_pub_key, serialized) do
    with {:ok, {sig, cypher}} <- deserialize(serialized),
         true <- PublicKey.verify(ver_pub_key, cypher, sig),
         {:ok, _} = ret <- PrivateKey.decrypt(dec_priv_key, cypher) do
      ret
    else
      false -> {:error, :invalid_signature}
      {:error, %{original: :decrypt_failed}, _} -> {:error, :cannot_decrypt}
      err -> err
    end
  end

  # Private stuff.

  @spec serialize(any) :: {:ok, binary}
  defp serialize(term), do: {:ok, :erlang.term_to_binary(term)}

  @spec deserialize(binary) :: term | {:error, :deserialization_error}
  defp deserialize(bin) do
    try do
      {:ok, :erlang.binary_to_term(bin)}
    rescue
      ArgumentError -> {:error, :deserialization_error}
    end
  end
end
