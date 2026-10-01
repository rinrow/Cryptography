using Crypto.Core.Interfaces;
using Crypto.Core.BitOperations;

namespace Crypto.Core.Modes;

/// <summary>
/// Режим OFB (Output Feedback) с полным блоком.
///
/// Шифрование:  O_0 = E(IV), O_i = E(O_{i-1}), C_i = P_i XOR O_i
/// Дешифрование: O_0 = E(IV), O_i = E(O_{i-1}), P_i = C_i XOR O_i
///
/// Особенности:
///   - Шифрование и дешифрование идентичны (используется только E).
///   - Обратная связь — по выходу E (keystream O_i), не по шифртексту.
///   - O_i не зависит от данных, только от IV.
///   - Цепочка O_i строго последовательна → параллелизм невозможен
///     без предвычисления всех O_i (что выходит за рамки одного вызова).
///
/// Режим stateless: состояние живёт в CipherState.PreviousCipher
/// (в нём хранится O_{i-1}, а не шифртекст).
/// </summary>
public sealed class OfbMode : IBlockCipherMode
{
    private byte[]? _iv;

    public OfbMode(int blockSize)
    {
        if (blockSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize));
        BlockSize = blockSize;
    }

    public int BlockSize { get; }
    public bool RequiresIV => true;
    public bool CanParallelizeEncryption => false;
    public bool CanParallelizeDecryption => false;

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

        // O_i = E(O_{i-1}), или O_0 = E(IV) для первого блока.
        // state.PreviousCipher хранит O_{i-1} (keystream), не шифртекст.
        byte[] previousO = state.PreviousCipher ?? _iv
            ?? throw new InvalidOperationException(
                "PreviousCipher is not set and IV was not configured.");

        byte[] keystream = cipher.EncryptBlock(previousO);

        // C_i = P_i XOR O_i
        byte[] cipherBlock = BitUtils.Xor(plainBlock, keystream);

        // Обновляем состояние: теперь предыдущий keystream = O_i.
        state.PreviousCipher = keystream;

        return cipherBlock;
    }

    public byte[] DecryptBlock(ISymmetricCipher cipher, byte[] cipherBlock, CipherState state)
    {
        // OFB симметричен: дешифрование = шифрование.
        return EncryptBlock(cipher, cipherBlock, state);
    }

    // ------------------------------------------------------------------

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