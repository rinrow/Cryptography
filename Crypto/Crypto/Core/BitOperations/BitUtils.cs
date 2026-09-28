using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Core.BitOperations
{
    /// <summary>
    /// Порядок индексации битов в байте.
    /// </summary>
    public enum BitIndexing
    {
        /// <summary>Бит 0 — младший (LSB). Нумерация: 0..7 в байте.</summary>
        FromLsb,

        /// <summary>Бит 0 — старший (MSB). Нумерация: 0..7 в байте.</summary>
        FromMsb
    }

    public static class BitUtils
    {
        public static int GetBit(byte[] data, int logicalIndex, BitIndexing indexing = BitIndexing.FromLsb, int startBitNumber = 0)
        {
            if (data is null) throw new ArgumentNullException(nameof(data));
            if (startBitNumber != 0 && startBitNumber != 1)
                throw new ArgumentException("startBitNumber must be 0 or 1", nameof(startBitNumber));

            int zeroBased = logicalIndex - startBitNumber;
            if (zeroBased < 0 || zeroBased >= data.Length * 8)
                throw new ArgumentOutOfRangeException(nameof(logicalIndex));

            int ind = logicalIndex - startBitNumber;
            int ibyte = ind / 8;
            int ibit = ind % 8;

            if (indexing == BitIndexing.FromMsb) ibit = 7 - ibit;

            return data[ibyte] >> ibit & 1;
        }

        public static void SetBit(byte[] data, int logicalIndex, int val, BitIndexing indexing = BitIndexing.FromLsb, int startBitNumber = 0)
        {
            if (data is null) throw new ArgumentNullException(nameof(data));
            if (startBitNumber != 0 && startBitNumber != 1)
                throw new ArgumentException("startBitNumber must be 0 or 1", nameof(startBitNumber));

            int zeroBased = logicalIndex - startBitNumber;
            if (zeroBased < 0 || zeroBased >= data.Length * 8)
                throw new ArgumentOutOfRangeException(nameof(logicalIndex));

            if (GetBit(data, logicalIndex, indexing, startBitNumber) == val) return;

            int ind = logicalIndex - startBitNumber;
            int ibyte = ind / 8;
            int ibit = ind % 8;

            if (indexing == BitIndexing.FromMsb) ibit = 7 - ibit;

            data[ibyte] ^= (byte)(1 << ibit);
        }

        public static byte[] Xor(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new ArgumentException("Arrays must have the same length for XOR.");

            var result = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }
    }
}
