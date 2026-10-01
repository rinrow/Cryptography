using System;
using System.Collections.Generic;
using System.Text;
using Crypto.Core.BitOperations;
using Crypto.Core.Interfaces;

namespace Crypto.DES
{
    public sealed class DesRoundFunction : IRoundFunction
    {
        public const int BlockSizeBytes = 4;
        public const int RoundKeySizeBytes = 6;

        public byte[] Transform(byte[] block, byte[] roundKey)
        {
            if (block is null) throw new ArgumentNullException(nameof(block));
            if (roundKey is null) throw new ArgumentNullException(nameof(roundKey));

            if (block.Length != BlockSizeBytes)
                throw new ArgumentException(
                    $"DES round block must be exactly {BlockSizeBytes} bytes, got {block.Length}.",
                    nameof(block));

            if (roundKey.Length != RoundKeySizeBytes)
                throw new ArgumentException(
                    $"DES round key must be exactly {RoundKeySizeBytes} bytes, got {roundKey.Length}.",
                    nameof(roundKey));

            return TransformFast(block, roundKey);

            byte[] expanded = BitPermutation.Permute(
                block,
                DesTables.E,
                BitIndexing.FromMsb, BitIndexing.FromMsb,
                inStartBitNumber: 1, outStartBitNumber: 1);

            byte[] xored = BitUtils.Xor(expanded, roundKey);

            byte[] substituted = ApplySBoxes(xored);

            byte[] result = BitPermutation.Permute(
                substituted,
                DesTables.P,
                BitIndexing.FromMsb, BitIndexing.FromMsb,
                inStartBitNumber: 1, outStartBitNumber: 1);

            return result;
        }

        public byte[] TransformFast(byte[] block, byte[] roundKey)
        {
            // block (4 байта) → uint R
            uint r = ((uint)block[0] << 24) | ((uint)block[1] << 16)
                   | ((uint)block[2] << 8) | block[3];

            // E-расширение: 32 → 48 бит через маску
            ulong expanded = 0;
            for (int i = 0; i < 48; i++)
            {
                int src = DesTables.E[i] - 1;   // 0..31
                ulong bit = (r >> (31 - src)) & 1;
                expanded |= bit << (47 - i);
            }

            // XOR с ключом (48 бит)
            ulong key = ((ulong)roundKey[0] << 40) | ((ulong)roundKey[1] << 32)
                      | ((ulong)roundKey[2] << 24) | ((ulong)roundKey[3] << 16)
                      | ((ulong)roundKey[4] << 8) | roundKey[5];
            expanded ^= key;

            // S-боксы: 48 → 32 бит
            uint substituted = 0;
            for (int box = 0; box < 8; box++)
            {
                int shift = 42 - box * 6;
                int sixBits = (int)((expanded >> shift) & 0x3F);
                int row = ((sixBits & 0x20) >> 4) | (sixBits & 1);
                int col = (sixBits >> 1) & 0xF;
                int sValue = DesTables.SBoxes[box, row, col];
                substituted = (substituted << 4) | (uint)sValue;
            }

            // P-перестановка: 32 → 32 бит
            uint result = 0;
            for (int i = 0; i < 32; i++)
            {
                int src = DesTables.P[i] - 1;
                uint bit = (substituted >> (31 - src)) & 1;
                result |= bit << (31 - i);
            }

            // uint → 4 байта
            return new byte[]
            {
                (byte)(result >> 24),
                (byte)(result >> 16),
                (byte)(result >> 8),
                (byte)result
            };
        }

        private static byte[] ApplySBoxes(byte[] input48)
        {
            // input48 — 6 байт, 48 бит. Нумерация битов: 1..48, отсчёт от MSB.
            // Разбиваем на 8 групп по 6 бит. Каждая группа — индекс S-бокса.
            var output = new byte[4]; // 32 бита
            int outputBitPos = 0;     // позиция в выходном массиве (0..31)

            for (int box = 0; box < 8; box++)
            {
                int bitOffset = box * 6;

                int b1 = GetBit(input48, bitOffset + 0); // внешний
                int b2 = GetBit(input48, bitOffset + 1);
                int b3 = GetBit(input48, bitOffset + 2);
                int b4 = GetBit(input48, bitOffset + 3);
                int b5 = GetBit(input48, bitOffset + 4);
                int b6 = GetBit(input48, bitOffset + 5); // внешний

                int row = (b1 << 1) | b6;                       // 0..3
                int col = (b2 << 3) | (b3 << 2) | (b4 << 1) | b5; // 0..15

                int sValue = DesTables.SBoxes[box, row, col];   // 0..15

                for (int k = 3; k >= 0; k--)
                {
                    int bit = (sValue >> k) & 1;
                    SetBit(output, outputBitPos++, bit);
                }
            }

            return output;
        }

        private static int GetBit(byte[] data, int bitPos)
        {
            return BitUtils.GetBit(data, bitPos, BitIndexing.FromMsb, 0);
        }

        private static void SetBit(byte[] data, int bitPos, int value)
        {
            BitUtils.SetBit(data, bitPos, value, BitIndexing.FromMsb, 0);
        }
    }
}
