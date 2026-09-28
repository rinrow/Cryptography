using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Core.BitOperations
{
    public static class BitPermutation
    {
        public static byte[] Permute(byte[] input, int[] pBlock, BitIndexing inIndexing, 
            BitIndexing outIndexing, int inStartBitNumber, int outStartBitNumber)
        {
            if (input is null) throw new ArgumentNullException(nameof(input));
            if (pBlock is null) throw new ArgumentNullException(nameof(pBlock));

            // res[i] = input[p[i]]
            byte[] res = new byte[(pBlock.Length + 7) / 8];

            for (int i = 0; i < pBlock.Length; i++)
            {
                int sourceZeroBased = pBlock[i] - inStartBitNumber;
                if (sourceZeroBased < 0 || sourceZeroBased >= input.Length * 8)
                    throw new ArgumentException(
                        $"P-блок ссылается на бит {pBlock[i]}, выходящий за границы входа ({input.Length * 8} бит).");


                int bit = BitUtils.GetBit(input, pBlock[i], inIndexing, inStartBitNumber);

                BitUtils.SetBit(res, i + outStartBitNumber, bit, outIndexing, outStartBitNumber);
            }

            return res;
        }
    }
}
