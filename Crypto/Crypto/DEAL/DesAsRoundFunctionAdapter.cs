using Crypto.Core.Interfaces;
using Crypto.DES;

namespace Crypto.DEAL;

/// <summary>
/// Адаптер: использует DES как раундовую функцию F для DEAL.
///
/// F(R, K) = DES_encrypt(R, K)
/// где R — 8 байт (правая половина блока DEAL),
///     K — 8 байт (раундовый ключ DEAL).
/// </summary>
public sealed class DesAsRoundFunctionAdapter : IRoundFunction
{
    public byte[] Transform(byte[] block, byte[] roundKey)
    {
        if (block is null) throw new ArgumentNullException(nameof(block));
        if (roundKey is null) throw new ArgumentNullException(nameof(roundKey));

        if (block.Length != 8)
            throw new ArgumentException(
                $"DEAL round block must be 8 bytes, got {block.Length}.", nameof(block));
        if (roundKey.Length != 8)
            throw new ArgumentException(
                $"DEAL round key must be 8 bytes, got {roundKey.Length}.", nameof(roundKey));

        var des = new DesCipher();
        des.SetKey(roundKey);
        return des.EncryptBlock(block);
    }
}