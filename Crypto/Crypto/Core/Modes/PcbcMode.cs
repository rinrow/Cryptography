using Crypto.Core.Interfaces;
using Crypto.Core.BitOperations;

namespace Crypto.Core.Modes;

/// <summary>
/// Режим PCBC (Propagating Cipher Block Chaining).
///
/// Шифрование:  C_i = E(P_i XOR (P_{i-1} XOR C_{i-1})),  P_{-1} XOR C_{-1} = IV
/// Дешифрование: P_i = D(C_i) XOR (P_{i-1} XOR C_{i-1})
///
/// Для первого блока обратная связь — только IV (аналогично CBC):
///   C_0 = E(P_0 XOR IV)
///   P_0 = D(C_0) XOR IV
///
/// Режим stateless: состояние живёт в CipherState.
/// Меняемые поля: PreviousCipher (C_{i-1}), PreviousPlain (P_{i-1}).
///
/// Параллелизм невозможен ни при шифровании, ни при дешифровании:
/// P_i зависит от P_{i-1}, который вычисляется последовательно.
/// </summary>
public sealed class PcbcMode : IBlockCipherMode
{
    private byte[]? _iv;

    public PcbcMode(int blockSize)
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

        // feedback = P_{i-1} XOR C_{i-1}, или IV для первого блока
        byte[] feedback = ComputeFeedback(state);

        // C_i = E(P_i XOR feedback)
        byte[] xored = BitUtils.Xor(plainBlock, feedback);
        byte[] cipherBlock = cipher.EncryptBlock(xored);

        // Обновляем состояние: P_{i-1} := P_i, C_{i-1} := C_i
        state.PreviousCipher = (byte[])cipherBlock.Clone();
        state.PreviousPlain = (byte[])plainBlock.Clone();

        return cipherBlock;
    }

    public byte[] DecryptBlock(ISymmetricCipher cipher, byte[] cipherBlock, CipherState state)
    {
        EnsureBlock(cipherBlock);
        EnsureState(state);

        // feedback = P_{i-1} XOR C_{i-1}, или IV для первого блока
        byte[] feedback = ComputeFeedback(state);

        // P_i = D(C_i) XOR feedback
        byte[] decrypted = cipher.DecryptBlock(cipherBlock);
        byte[] plainBlock = BitUtils.Xor(decrypted, feedback);

        // Обновляем состояние: P_{i-1} := P_i, C_{i-1} := C_i
        state.PreviousCipher = (byte[])cipherBlock.Clone();
        state.PreviousPlain = (byte[])plainBlock.Clone();

        return plainBlock;
    }

    // ------------------------------------------------------------------

    /// <summary>
    /// Вычисляет feedback = P_{i-1} XOR C_{i-1}.
    /// Для первого блока (PreviousPlain == null) возвращает IV.
    /// </summary>
    private byte[] ComputeFeedback(CipherState state)
    {
        if (state.PreviousPlain is null)
        {
            // Первый блок: feedback = IV
            return _iv
                ?? throw new InvalidOperationException(
                    "PCBC requires IV for the first block, but it was not set.");
        }

        if (state.PreviousCipher is null)
            throw new InvalidOperationException(
                "PCBC state is inconsistent: PreviousPlain is set, " +
                "but PreviousCipher is null.");

        return BitUtils.Xor(state.PreviousPlain, state.PreviousCipher);
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