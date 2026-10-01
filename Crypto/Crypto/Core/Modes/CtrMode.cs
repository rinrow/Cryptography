using Crypto.Core.Interfaces;
using Crypto.Core.BitOperations;

namespace Crypto.Core.Modes;

/// <summary>
/// Режим CTR (Counter).
///
/// Шифрование:  O_i = E(IV + i), C_i = P_i XOR O_i
/// Дешифрование: O_i = E(IV + i), P_i = C_i XOR O_i
///
/// Особенности:
///   - Шифрование и дешифрование идентичны (используется только E).
///   - O_i зависит только от номера блока i, не от данных.
///   - Полный параллелизм в оба направления.
///   - IV — целый блок (BlockSize байт). counter_i = IV + i,
///     где сложение — big-endian с переносом через байты.
///
/// Режим stateless: состояние — CipherState.Counter (номер блока).
/// </summary>
public sealed class CtrMode : IBlockCipherMode
{
    private byte[]? _iv;

    public CtrMode(int blockSize)
    {
        if (blockSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize));

        BlockSize = blockSize;
    }

    public int BlockSize { get; }
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

        _iv = (byte[])iv.Clone();
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
        // CTR симметричен.
        return EncryptBlock(cipher, cipherBlock, state);
    }

    // ------------------------------------------------------------------

    /// <summary>
    /// Формирует counter-block: counter_i = IV + i.
    /// Сложение big-endian с переносом через байты.
    /// </summary>
    private byte[] BuildCounterBlock(long counter)
    {
        if (_iv is null)
            throw new InvalidOperationException(
                "IV is not set. Call SetIV before EncryptBlock/DecryptBlock.");

        if (counter < 0)
            throw new ArgumentOutOfRangeException(nameof(counter));

        // Копируем IV, чтобы не портить.
        byte[] result = (byte[])_iv.Clone();

        // Прибавляем counter к result, начиная с младшего байта (индекс BlockSize - 1).
        long carry = counter;
        int byteIndex = BlockSize - 1;

        while (carry > 0 && byteIndex >= 0)
        {
            long sum = result[byteIndex] + (carry & 0xFF);
            result[byteIndex] = (byte)(sum & 0xFF);
            carry = (carry >> 8) + (sum >> 8);
            byteIndex--;
        }

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