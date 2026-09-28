using Crypto.Core.Interfaces;
using Crypto.Core.BitOperations;
using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Feistel
{
    public sealed class FeistelNetwork
    {
        private readonly IKeyExpansion _keyExpansion;
        private readonly IRoundFunction _roundFunction;

        public FeistelNetwork(IKeyExpansion keyExpansion, IRoundFunction roundFunction)
        {
            _keyExpansion = keyExpansion ?? throw new ArgumentNullException(nameof(keyExpansion));
            _roundFunction = roundFunction ?? throw new ArgumentNullException(nameof(roundFunction));
        }

        public byte[][] ExpandKey(byte[] key)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));
            return _keyExpansion.ExpandKey(key);
        }

        public byte[] EncryptBlock(byte[] block, byte[][] roundKeys)
        {
            ValidateInputs(block, roundKeys);

            int half = block.Length / 2;
            byte[] left = block[..half];
            byte[] right = block[half..];

            for (int i = 0; i < roundKeys.Length; i++)
            {
                byte[] f = _roundFunction.Transform(right, roundKeys[i]);
                EnsureRoundOutput(f, half);

                byte[] newRight = BitUtils.Xor(left, f);
                left = right;
                right = newRight;
            }

            return Concat(right, left);
        }

        public byte[] DecryptBlock(byte[] block, byte[][] roundKeys)
        {
            ValidateInputs(block, roundKeys);

            int half = block.Length / 2;
            byte[] left = block[..half];
            byte[] right = block[half..];

            for (int i = roundKeys.Length - 1; i >= 0; i--)
            {
                byte[] f = _roundFunction.Transform(right, roundKeys[i]);
                EnsureRoundOutput(f, half);

                byte[] newRight = BitUtils.Xor(left, f);
                left = right;
                right = newRight;
            }

            return Concat(right, left);
        }

        private static void ValidateInputs(byte[] block, byte[][] roundKeys)
        {
            if (block is null) throw new ArgumentNullException(nameof(block));
            if (roundKeys is null) throw new ArgumentNullException(nameof(roundKeys));

            if (block.Length == 0 || block.Length % 2 != 0)
                throw new ArgumentException(
                    "Block length must be a positive even number.", nameof(block));

            if (roundKeys.Length == 0)
                throw new ArgumentException(
                    "Round keys array must not be empty.", nameof(roundKeys));
        }

        private static void EnsureRoundOutput(byte[] f, int expectedHalf)
        {
            if (f is null)
                throw new InvalidOperationException(
                    "Round function returned null.");

            if (f.Length != expectedHalf)
                throw new InvalidOperationException(
                    $"Round function returned {f.Length} bytes, expected {expectedHalf}.");
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
}
