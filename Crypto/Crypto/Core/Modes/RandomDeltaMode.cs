using Crypto.Core.Interfaces;
using Crypto.Core.BitOperations;

namespace Crypto.Core.Modes;

/// <summary>
/// Режим Random Delta.
///
/// Шифрование:  O_i = E(counter_i), C_i = P_i XOR O_i
/// Дешифрование: O_i = E(counter_i), P_i = C_i XOR O_i
/// где counter_i = IV + delta * i  (mod 2^(BlockSize*8)).
///
/// IV_full делится на две половины:
///   - левая  → IV (начальный counter),
///   - правая → delta (шаг счётчика).
///
/// Особенности:
///   - Шифрование и дешифрование идентичны (используется только E).
///   - Полный параллелизм в оба направления.
///   - Переполнение разрешено: все операции по модулю 2^(BlockSize*8).
///
/// Режим stateless: состояние — CipherState.Counter (номер блока i).
/// </summary>
public sealed class RandomDeltaMode : IBlockCipherMode
{
    private byte[]? _iv;      // левая половина IV_full
    private byte[]? _delta;   // правая половина IV_full

    public RandomDeltaMode(int blockSize)
    {
        if (blockSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize));
        if (blockSize % 2 != 0)
            throw new ArgumentException(
                "Block size must be even for Random Delta " +
                "(IV split into two equal halves).",
                nameof(blockSize));

        BlockSize = blockSize;
        HalfSize = blockSize / 2;
    }

    public int BlockSize { get; }

    /// <summary>Размер каждой половины IV (IV и delta).</summary>
    public int HalfSize { get; }

    public bool RequiresIV => true;
    public bool CanParallelizeEncryption => true;
    public bool CanParallelizeDecryption => true;

    public void SetIV(byte[] iv)
    {
        if (iv is null) throw new ArgumentNullException(nameof(iv));
        if (iv.Length != BlockSize)
            throw new ArgumentException(
                $"IV must be exactly {BlockSize} bytes, got {iv.Length}.",
                nameof(iv));

        _iv = new byte[HalfSize];
        _delta = new byte[HalfSize];
        Buffer.BlockCopy(iv, 0, _iv, 0, HalfSize);
        Buffer.BlockCopy(iv, HalfSize, _delta, 0, HalfSize);
    }

    public byte[] EncryptBlock(ISymmetricCipher cipher, byte[] plainBlock, CipherState state)
    {
        EnsureBlock(plainBlock);
        EnsureState(state);

        byte[] counterBlock = BuildCounterBlock(state.Counter);
        byte[] keystream = cipher.EncryptBlock(counterBlock);
        byte[] cipherBlock = BitUtils.Xor(plainBlock, keystream);

        state.Counter++;
        return cipherBlock;
    }

    public byte[] DecryptBlock(ISymmetricCipher cipher, byte[] cipherBlock, CipherState state)
    {
        // Random Delta симметричен: дешифрование = шифрование.
        return EncryptBlock(cipher, cipherBlock, state);
    }

    // ------------------------------------------------------------------

    /// <summary>
    /// Формирует counter_i = IV + delta * i (mod 2^(BlockSize*8)).
    ///
    /// Числа трактуются как big-endian: counter_block[0] — старший байт,
    /// counter_block[BlockSize-1] — младший.
    /// </summary>
    private byte[] BuildCounterBlock(long i)
    {
        if (_iv is null || _delta is null)
            throw new InvalidOperationException(
                "IV is not set. Call SetIV before EncryptBlock/DecryptBlock.");

        if (i < 0)
            throw new ArgumentOutOfRangeException(nameof(i));

        // counter = IV + delta * i (mod 2^(BlockSize*8)).
        //
        // Работаем с числами произвольной длины через два буфера:
        //   - product = delta * i        (HalfSize * 2 байт, но нам нужен мод 2^(BlockSize*8))
        //   - counter = IV + product      (BlockSize байт, mod 2^(BlockSize*8))
        //
        // Проще: будем выполнять арифметику побайтово "в столбик".

        byte[] counter = new byte[BlockSize];

        // Копируем IV в старшую половину counter (big-endian: IV — старшие байты).
        Buffer.BlockCopy(_iv, 0, counter, 0, HalfSize);

        // Прибавляем delta * i.
        // delta * i вычисляем пошагово: складываем delta i раз? Нет — умножаем.
        // Умножение delta на i даёт число длиной до HalfSize*8 + log2(i) бит.
        // Но по модулю 2^(BlockSize*8) нам важны только младшие BlockSize байт.

        // Считаем delta * i как byte[] длиной BlockSize (little-endian для удобства).
        byte[] deltaXi = MultiplyByLong(_delta, i, BlockSize);

        // Прибавляем deltaXi к counter (оба — big-endian).
        AddInPlace(counter, deltaXi);

        return counter;
    }

    /// <summary>
    /// Умножает big-endian число (длиной HalfSize байт) на long i.
    /// Возвращает результат длиной BlockSize байт (big-endian),
    /// обрезанный по модулю 2^(BlockSize*8).
    /// </summary>
    private static byte[] MultiplyByLong(byte[] bigEndianValue, long multiplier, int resultSize)
    {
        // Работаем в little-endian для удобства.
        // littleEndianValue[0] — младший байт.
        byte[] littleValue = Reverse(bigEndianValue);

        // Умножаем на multiplier.
        // Результат может занимать больше байт, чем littleValue.Length,
        // но мы обрежем до resultSize.
        byte[] product = new byte[resultSize];

        long carry = 0;
        for (int i = 0; i < littleValue.Length; i++)
        {
            long cur = (long)littleValue[i] * multiplier + carry;
            if (i < resultSize)
                product[i] = (byte)(cur & 0xFF);
            carry = cur >> 8;
        }

        // Продолжаем выкладывать carry в оставшиеся байты.
        int idx = littleValue.Length;
        while (carry > 0 && idx < resultSize)
        {
            product[idx] = (byte)(carry & 0xFF);
            carry >>= 8;
            idx++;
        }

        // Если после заполнения resultSize остался carry — он отбрасывается
        // (это и есть mod 2^(resultSize*8)).

        // Возвращаем в big-endian.
        return Reverse(product);
    }

    /// <summary>
    /// Сложение big-endian чисел: a += b, по модулю 2^(a.Length*8).
    /// </summary>
    private static void AddInPlace(byte[] a, byte[] b)
    {
        int carry = 0;
        for (int i = a.Length - 1; i >= 0; i--)
        {
            int sum = a[i] + b[i] + carry;
            a[i] = (byte)(sum & 0xFF);
            carry = sum >> 8;
        }
        // carry за пределами a.Length отбрасывается — mod 2^(a.Length*8).
    }

    private static byte[] Reverse(byte[] src)
    {
        byte[] result = new byte[src.Length];
        for (int i = 0; i < src.Length; i++)
            result[i] = src[src.Length - 1 - i];
        return result;
    }

    private void EnsureBlock(byte[] block)
    {
        if (block is null) throw new ArgumentNullException(nameof(block));
        if (block.Length != BlockSize)
            throw new ArgumentException(
                $"Block must be exactly {BlockSize} bytes, got {block.Length}.",
                nameof(block));
    }

    private void EnsureState(CipherState state)
    {
        if (state is null) throw new ArgumentNullException(nameof(state));
    }
}