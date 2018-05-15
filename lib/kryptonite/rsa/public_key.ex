defmodule Kryptonite.RSA.PublicKey do
  @moduledoc """
  This module provides abstraction functions based around the manipulation of
  public keys.
  """
  alias Kryptonite.RSA

  @me __MODULE__

  @type native :: :public_key.public_key()

  @type t :: %__MODULE__{public_modulus: pos_integer, public_exponent: pos_integer}
  defstruct [:public_modulus, :public_exponent]

  @doc """
  Performs the conversion of an underlying Erlang's public key into the library's
  easy to use struct.
  """
  @spec from_native(any) :: {:ok, t} | {:error, any}
  def from_native({:RSAPublicKey, pm, pe}) do
    {:ok, %@me{public_modulus: pm, public_exponent: pe}}
  end

  def from_native(_), do: {:error, :invalid_native}

  @doc """
  Because this module uses Erlang lower level functions, it has to also use the
  native public key format that those functions expect - this helper method is
  therefore provided.
  """
  @spec to_native(any) :: {:ok, native} | {:error, any}
  def to_native(%@me{} = t), do: {:ok, {:RSAPublicKey, t.public_modulus, t.public_exponent}}

  def to_native(_), do: {:error, :invalid_public_key}

  @doc """
  Verifies that a given `signature` matches a provided `messages` and ensures that it
  was issued using the private key that matches the given public `key`.
  """
  @spec verify(t, RSA.message(), RSA.signature()) :: boolean | {:error, :verification_error}
  def verify(%@me{} = key, msg, sig) do
    with {:ok, native_key} <- to_native(key) do
      try do
        :public_key.verify(msg, :sha256, sig, native_key)
      catch
        _, err -> {:error, {:verification_failure, err}}
      end
    end
  end

  def verify(_, _, _), do: {:error, :invalid_public_key}

  @doc """
  Encrypts a given `message` using the provided public `key`. The resulting cypher
  can later be decrypted using the `Kryptonite.RSA.PrivateKey.decrypt/2` function
  using the matching private key.
  """
  @spec encrypt(t, RSA.message()) :: {:ok, RSA.cypher()} | {:error, any}
  def encrypt(%@me{} = key, msg) do
    with {:ok, native_key} <- to_native(key) do
      try do
        {:ok, :public_key.encrypt_public(msg, native_key)}
      catch
        _, err -> {:error, {:encryption_failure, err}}
      end
    end
  end

  def encrypt(_, _), do: {:error, :invalid_public_key}

  @doc """
  Decrypts a cypher that was generated using the matching private key. Note that
  this is not a common way of doing things and you will not be likelly to use this
  function. Instead, see `PrivateKey.decrypt/2` function.
  """
  @spec decrypt(t, RSA.cypher()) :: {:ok, RSA.message()} | {:error, any}
  def decrypt(%@me{} = key, cypher_bytes) do
    with {:ok, native_key} <- to_native(key) do
      try do
        {:ok, :public_key.decrypt_public(cypher_bytes, native_key)}
      catch
        _, err -> {:error, {:decryption_failure, err}}
      end
    end
  end

  def decrypt(_, _), do: {:error, :invalid_public_key}
end
