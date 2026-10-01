using Crypto.Core.Interfaces;
using Crypto.Core.BitOperations;
using Crypto.DES;

namespace Crypto.DEAL;

/// <summary>
/// Расширение ключа DEAL (упрощённая схема для лабораторной).
///
/// Вход: 128-битный ключ (16 байт).
/// Выход: 6 раундовых ключей по 8 байт.
///
/// Схема:
///   K_A = key[0..8], K_B = key[8..16]
///   extended = K_A || K_B || K_A (24 байта)
///   RK_i = DES(extended[i*8 .. i*8+8], const_i)
///   где const_i = 8-байтовый блок со значением i в младшем байте.
/// </summary>
public sealed class DealKeyExpansion : IKeyExpansion
{
    public const int Rounds = 6;
    public const int KeySizeBytes = 16;
    private static readonly byte[] K =
        { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

    public byte[][] ExpandKey(byte[] key)
    {
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (key.Length != KeySizeBytes)
            throw new ArgumentException(
                $"DEAL key must be {KeySizeBytes} bytes, got {key.Length}.", nameof(key));

        byte[] k1 = new byte[8];
        byte[] k2 = new byte[8];
        Buffer.BlockCopy(key, 0, k1, 0, 8);
        Buffer.BlockCopy(key, 8, k2, 0, 8);

        byte[][] roundKeys = new byte[Rounds][];
        var des = new DesCipher();
        des.SetKey(K);

        byte[] tmp = new byte[8];

        roundKeys[0] = des.EncryptBlock(k1);

        roundKeys[1] = des.EncryptBlock(BitUtils.Xor(k2, roundKeys[0]));

        BitUtils.SetBit(tmp, 0, 1, BitIndexing.FromMsb);
        roundKeys[2] = des.EncryptBlock(BitUtils.Xor(BitUtils.Xor(k1, tmp), roundKeys[1]));
        BitUtils.SetBit(tmp, 0, 0, BitIndexing.FromMsb);

        BitUtils.SetBit(tmp, 1, 1, BitIndexing.FromMsb);
        roundKeys[3] = des.EncryptBlock(BitUtils.Xor(BitUtils.Xor(k2, tmp), roundKeys[2]));
        BitUtils.SetBit(tmp, 1, 0, BitIndexing.FromMsb);

        BitUtils.SetBit(tmp, 3, 1, BitIndexing.FromMsb);
        roundKeys[4] = des.EncryptBlock(BitUtils.Xor(BitUtils.Xor(k1, tmp), roundKeys[3]));
        BitUtils.SetBit(tmp, 3, 0, BitIndexing.FromMsb);

        BitUtils.SetBit(tmp, 7, 1, BitIndexing.FromMsb);
        roundKeys[5] = des.EncryptBlock(BitUtils.Xor(BitUtils.Xor(k2, tmp), roundKeys[4]));
        BitUtils.SetBit(tmp, 7, 0, BitIndexing.FromMsb);


        return roundKeys;
    }
}