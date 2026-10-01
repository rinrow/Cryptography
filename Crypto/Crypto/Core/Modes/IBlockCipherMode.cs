using Crypto.Core.Interfaces;
using Crypto.Core.Modes;

public interface IBlockCipherMode
{
    int BlockSize { get; }
    bool RequiresIV { get; }

    /// <summary>Можно ли параллелить шифрование (C_i не зависит от C_{i-1}).</summary>
    bool CanParallelizeEncryption { get; }

    /// <summary>Можно ли параллелить дешифрование (P_i зависит только от C_i и C_{i-1}).</summary>
    bool CanParallelizeDecryption { get; }

    void SetIV(byte[] iv);

    byte[] EncryptBlock(ISymmetricCipher cipher, byte[] plainBlock, CipherState state);
    byte[] DecryptBlock(ISymmetricCipher cipher, byte[] cipherBlock, CipherState state);
}