defmodule Kryptonite.RSA.PrivateKey do
  @moduledoc false
  alias Kryptonite.RSA
  alias Kryptonite.RSA.PublicKey

  @me __MODULE__

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

  @spec new(pos_integer, pos_integer) :: t | {:error, any}
  def new(size_in_bits \\ 1024, public_exponent \\ 65_537) when size_in_bits >= 256 do
    {:rsa, size_in_bits, public_exponent}
    |> :public_key.generate_key()
    |> from_native()
  catch
    _, err -> {:error, {:key_generation_error, err}}
  end

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

  @spec to_native(t) :: native | {:error, any}
  def to_native(%@me{version: :"two-prime"} = t),
    do:
      {:ok,
       {:RSAPrivateKey, :"two-prime", t.public_modulus, t.public_exponent, t.private_exponent,
        t.prime_one, t.prime_two, t.exponent_one, t.exponent_two, t.ctr_coefficient,
        t.other_prime_infos}}

  def to_native(%@me{}), do: {:error, :invalid_native_version}

  def to_native(_), do: {:error, :invalid_private_key}

  @spec public_key(t) :: PublicKey.t() | {:error, any}
  def public_key(%@me{version: :"two-prime", public_modulus: pm, public_exponent: pe}),
    do: {:ok, %PublicKey{public_modulus: pm, public_exponent: pe}}

  def public_key(%@me{}), do: {:error, :invalid_native_version}

  def public_key(_), do: {:error, :invalid_private_key}

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
end
