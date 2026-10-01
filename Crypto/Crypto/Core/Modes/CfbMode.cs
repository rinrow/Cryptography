using Crypto.Core.Interfaces;
using Crypto.Core.BitOperations;

namespace Crypto.Core.Modes;

/// <summary>
/// Режим CFB (Cipher Feedback) с полным блоком (CFB-64 для DES).
///
/// Шифрование:  C_i = P_i XOR E(C_{i-1}),  C_{-1} = IV
/// Дешифрование: P_i = C_i XOR E(C_{i-1}),  C_{-1} = IV
///
/// Особенности:
///   - E применяется и при шифровании, и при дешифровании (D не нужен).
///   - Обратная связь — по шифртексту C_{i-1}.
///   - Шифрование последовательно (C_i зависит от C_{i-1}).
///   - Дешифрование параллелится (C_i и C_{i-1} известны заранее).
///
/// Режим stateless: состояние живёт в CipherState.PreviousCipher.
/// </summary>
public sealed class CfbMode : IBlockCipherMode
{
    private byte[]? _iv;

    public CfbMode(int blockSize)
    {
        if (blockSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize));
        BlockSize = blockSize;
    }

    public int BlockSize { get; }
    public bool RequiresIV => true;
    public bool CanParallelizeEncryption => false;
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

        // C_{i-1}: либо из state (параллельный путь), либо IV (первый блок).
        byte[] previous = state.PreviousCipher ?? _iv
            ?? throw new InvalidOperationException(
                "PreviousCipher is not set and IV was not configured.");

        // keystream = E(C_{i-1})
        byte[] keystream = cipher.EncryptBlock(previous);

        // C_i = P_i XOR keystream
        byte[] cipherBlock = BitUtils.Xor(plainBlock, keystream);

        // Обновляем состояние: теперь предыдущий = свежий шифртекст.
        state.PreviousCipher = (byte[])cipherBlock.Clone();

        return cipherBlock;
    }

    public byte[] DecryptBlock(ISymmetricCipher cipher, byte[] cipherBlock, CipherState state)
    {
        EnsureBlock(cipherBlock);
        EnsureState(state);

        byte[] previous = state.PreviousCipher ?? _iv
            ?? throw new InvalidOperationException(
                "PreviousCipher is not set and IV was not configured.");

        // keystream = E(C_{i-1})
        byte[] keystream = cipher.EncryptBlock(previous);

        // P_i = C_i XOR keystream
        byte[] plainBlock = BitUtils.Xor(cipherBlock, keystream);

        // Обновляем состояние: теперь предыдущий = текущий шифртекст.
        state.PreviousCipher = (byte[])cipherBlock.Clone();

        return plainBlock;
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