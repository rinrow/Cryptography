using Crypto.Core.BitOperations;
using Crypto.Core.Interfaces;
using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.DES
{

    /// <summary>
    /// Реализация процедуры расширения ключа для алгоритма DES
    /// (FIPS PUB 46-3, раздел «Key Schedule»).
    ///
    /// Вход:  64-битный ключ (8 байт). Биты чётности игнорируются
    ///        на этапе PC-1 (таблица выбирает 56 из 64 бит).
    /// Выход: 16 раундовых ключей по 48 бит (6 байт каждый).
    /// </summary>
    public sealed class DesKeyExpansion : IKeyExpansion
    {
        public const int KeySizeBytes = 8;
        public const int Rounds = 16;
        public const int RoundKeySizeBytes = 6;

        private const ulong Mask28 = 0xFFFFFFF;

        /// <summary>
        /// Выполняет расширение 64-битного ключа в 16 раундовых ключей по 48 бит.
        /// </summary>
        /// <param name="key">Входной ключ DES — ровно 8 байт.</param>
        /// <returns>Массив из 16 раундовых ключей, каждый — 6 байт.</returns>
        public byte[][] ExpandKey(byte[] key)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != KeySizeBytes)
                throw new ArgumentException(
                    $"DES key must be exactly {KeySizeBytes} bytes, got {key.Length}.",
                    nameof(key));

            
            byte[] permutedKey = BitPermutation.Permute(
                key,
                DesTables.PC1,
                BitIndexing.FromMsb, BitIndexing.FromMsb,
                inStartBitNumber: 1, outStartBitNumber: 1);

            ulong c = 0;
            ulong d = 0;
            SplitIntoHalves(permutedKey, out c, out d);

            var roundKeys = new byte[Rounds][];

            for (int i = 0; i < Rounds; i++)
            {
                c = CyclicShiftLeft28(c, DesTables.Shifts[i]);
                d = CyclicShiftLeft28(d, DesTables.Shifts[i]);

                ulong cd = (c << 28) | d;

                byte[] cdBytes = UlongTo56BitBytes(cd); // 7 байт

                byte[] roundKey = BitPermutation.Permute(
                    cdBytes,
                    DesTables.PC2,
                    BitIndexing.FromMsb, BitIndexing.FromMsb,
                    inStartBitNumber: 1, outStartBitNumber: 1);

                roundKeys[i] = roundKey;
            }

            return roundKeys;
        }


        private static void SplitIntoHalves(byte[] permutedKey, out ulong c, out ulong d)
        {
            ulong value = 0;
            for (int i = 0; i < 7; i++)
            {
                value <<= 8;
                value |= permutedKey[i];
            }

            c = (value >> 28) & Mask28;
            d = value & Mask28;
        }

        private static ulong CyclicShiftLeft28(ulong value, int shift)
        {
            return ((value << shift) | (value >> (28 - shift))) & Mask28;
        }

        private static byte[] UlongTo56BitBytes(ulong value)
        {
            byte[] res = new byte[7];
            for (int i = 0; i < 7; i++)
            {
                res[6 - i] = (byte)(value & 0xFF); 
                value >>= 8;
            }
            return res;
        }
    }
}
