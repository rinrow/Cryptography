using Crypto.Core.Interfaces;

namespace Crypto.Core.Modes;

/// <summary>
/// Режим ECB (Electronic Codebook).
///
/// Каждый блок шифруется/дешифруется независимо:
///   C_i = E(P_i)
///   P_i = D(C_i)
///
/// IV не используется. Режим не хранит состояние,
/// поэтому один экземпляр можно переиспользовать.
/// </summary>
public sealed class EcbMode : IBlockCipherMode
{
    public EcbMode(int blockSize)
    {
        if (blockSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize));

        BlockSize = blockSize;
    }

    public int BlockSize { get; }

    public bool RequiresIV => false;

    public bool CanParallelizeEncryption => true;

    public bool CanParallelizeDecryption => true;

    public void SetIV(byte[] iv)
    {
        // ECB не использует IV. Молча игнорируем,
        // чтобы контекст мог вызывать SetIV единообразно.
    }

    public byte[] EncryptBlock(ISymmetricCipher cipher, byte[] plainBlock, CipherState st)
    {
        EnsureBlock(plainBlock);
        return cipher.EncryptBlock(plainBlock);
    }

    public byte[] DecryptBlock(ISymmetricCipher cipher, byte[] cipherBlock, CipherState st)
    {
        EnsureBlock(cipherBlock);
        return cipher.DecryptBlock(cipherBlock);
    }

    private void EnsureBlock(byte[] block)
    {
        if (block is null) throw new ArgumentNullException(nameof(block));
        if (block.Length != BlockSize)
            throw new ArgumentException(
                $"Block must be exactly {BlockSize} bytes, got {block.Length}.",
                nameof(block));
    }
}