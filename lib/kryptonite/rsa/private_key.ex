defmodule Kryptonite.RSA.PrivateKey do
  @moduledoc """
  This module provides abstraction around Erlang's `:public_key` functions that
  aim to manipulate private keys.

  Most if not all of the functions in this module are meant to be easily compatible
  with elixir's `with` construct, and therefore returns something that can always
  be pattern-matched for success (Typically a `{:ok, value}` tuple).
  """

  alias Kryptonite.RSA
  alias Kryptonite.RSA.PublicKey

  @me __MODULE__
  @fermats [
    3,
    5,
    17,
    257,
    65_537,
    4_294_967_297,
    18_446_744_073_709_551_617,
    340_282_366_920_938_463_463_374_607_431_768_211_457,
    115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_937
  ]

  @type native :: :public_key.private_key()

  @type t :: %__MODULE__{
          version: :"two-prime",
          public_modulus: pos_integer,
          public_exponent: pos_integer,
          private_exponent: pos_integer,
          prime_one: pos_integer,
          prime_two: pos_integer,
          exponent_one: pos_integer,
          exponent_two: pos_integer,
          ctr_coefficient: pos_integer,
          other_prime_infos: atom
        }
  defstruct [
    :version,
    :public_modulus,
    :public_exponent,
    :private_exponent,
    :prime_one,
    :prime_two,
    :exponent_one,
    :exponent_two,
    :ctr_coefficient,
    :other_prime_infos
  ]

  @doc """
  This function is used to generate a new private key given a `size_in_bits` and
  a `public_exponent`, both of which have sane default values.
  """
  @spec new(pos_integer, pos_integer) :: t | {:error, any}
  def new(size_in_bits \\ 1024, public_exponent \\ 65_537) do
    with true <- ensure_valid_size(size_in_bits),
         true <- ensure_valid_fermat(public_exponent) do
      {:rsa, size_in_bits, public_exponent}
      |> :public_key.generate_key()
      |> from_native()
    end
  end

  @doc """
  Can be used when an Erlang native private key has to be converted in a format that
  this library will understand.
  """
  @spec from_native(native) :: t | {:error, any}
  def from_native({:RSAPrivateKey, :"two-prime" = v, pm, pe, pve, pm1, pm2, e1, e2, ctrc, opi}),
    do:
      {:ok,
       %@me{
         version: v,
         public_modulus: pm,
         public_exponent: pe,
         private_exponent: pve,
         prime_one: pm1,
         prime_two: pm2,
         exponent_one: e1,
         exponent_two: e2,
         ctr_coefficient: ctrc,
         other_prime_infos: opi
       }}

  def from_native(_), do: {:error, :invalid_native}

  @doc """
  Most of this module's function internally use Erlang's native format when performing
  cryptographic operations; therefore this function is provided as a helper.
  """
  @spec to_native(t) :: native | {:error, any}
  def to_native(%@me{version: :"two-prime"} = t),
    do:
      {:ok,
       {:RSAPrivateKey, :"two-prime", t.public_modulus, t.public_exponent, t.private_exponent,
        t.prime_one, t.prime_two, t.exponent_one, t.exponent_two, t.ctr_coefficient,
        t.other_prime_infos}}

  def to_native(%@me{}), do: {:error, :invalid_native_version}

  def to_native(_), do: {:error, :invalid_private_key}

  @doc """
  Allows to extract the public components from a private key and return a
  `Kryptonite.RSA.PublicKey.t()` construct, which later can be used to perform
  various cryptographic operations such as decrypting cypher messages.
  """
  @spec public_key(t) :: PublicKey.t() | {:error, any}
  def public_key(%@me{version: :"two-prime", public_modulus: pm, public_exponent: pe}),
    do: {:ok, %PublicKey{public_modulus: pm, public_exponent: pe}}

  def public_key(%@me{}), do: {:error, :invalid_native_version}

  def public_key(_), do: {:error, :invalid_private_key}

  @doc """
  Signs a given `message` using the provided private `key`.
  """
  @spec sign(t, RSA.message()) :: {:ok, RSA.signature()} | {:error, any}
  def sign(%@me{} = key, msg) do
    with {:ok, native_key} <- to_native(key) do
      try do
        {:ok, :public_key.sign(msg, :sha256, native_key)}
      catch
        _, err -> {:error, {:signing_failure, err}}
      end
    end
  end

  def sign(_, _), do: {:error, :invalid_private_key}

  @doc """
  Performs the encryption of a given `message` using the provided private `key`.
  Note that this function will rarelly be used, as the only way to decrypt the
  generated cypher would be using the public key, which isn't usually the intended
  way of exchanging secure messages.
  """
  @spec encrypt(t, RSA.message()) :: {:ok, RSA.cypher()} | {:error, any}
  def encrypt(%@me{} = key, msg) do
    with {:ok, native_key} <- to_native(key) do
      try do
        {:ok, :public_key.encrypt_private(msg, native_key)}
      catch
        _, err -> {:error, {:encryption_failure, err}}
      end
    end
  end

  def encrypt(_, _), do: {:error, :invalid_private_key}

  @doc """
  Performs the decryption of a given `message` using the provided private `key`.
  The message has to be encrypted using the matching public key, or an error will
  be returned.
  """
  @spec decrypt(t, RSA.cypher()) :: {:ok, RSA.message()} | {:error, any}
  def decrypt(%@me{} = key, cypher_bytes) do
    with {:ok, native_key} <- to_native(key) do
      try do
        {:ok, :public_key.decrypt_private(cypher_bytes, native_key)}
      catch
        _, err -> {:error, {:decryption_failure, err}}
      end
    end
  end

  def decrypt(_, _), do: {:error, :invalid_private_key}

  # Private stuff.

  @spec ensure_valid_size(pos_integer) :: true | {:error, any}
  defp ensure_valid_size(size_in_bits) when size_in_bits < 256, do: {:error, :invalid_key_size}

  defp ensure_valid_size(s),
    do: rem(s, 512) == 0 || {:error, :invalid_key_size}

  @spec ensure_valid_fermat(pos_integer) :: true | {:error, :invalid_public_exponent}
  defp ensure_valid_fermat(e),
    do: e in @fermats || {:error, :invalid_public_exponent}
end
