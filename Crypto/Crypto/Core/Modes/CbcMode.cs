using Crypto.Core.Interfaces;
using Crypto.Core.BitOperations;

namespace Crypto.Core.Modes;

public sealed class CbcMode : IBlockCipherMode
{
    private byte[]? _iv;

    public CbcMode(int blockSize)
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

        // previous = state.PreviousCipher, если задан; иначе — _iv
        byte[] previous = state.PreviousCipher ?? _iv
            ?? throw new InvalidOperationException(
                "PreviousCipher is not set and IV was not configured.");

        // C_i = E(P_i XOR C_{i-1})
        byte[] xored = BitUtils.Xor(plainBlock, previous);
        byte[] cipherBlock = cipher.EncryptBlock(xored);

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

        // P_i = D(C_i) XOR C_{i-1}
        byte[] decrypted = cipher.DecryptBlock(cipherBlock);
        byte[] plainBlock = BitUtils.Xor(decrypted, previous);

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