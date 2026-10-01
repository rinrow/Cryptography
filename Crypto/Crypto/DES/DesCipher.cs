using Crypto.Core.BitOperations;
using Crypto.Core.Interfaces;
using Crypto.Feistel;
using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.DES
{
    public sealed class DesCipher : ISymmetricCipher
    {
        public const int BlockSizeBytes = 8;
        public const int KeySizeBytes = 8;

        private readonly FeistelNetwork _feistel;
        private byte[][]? _roundKeys;

        public DesCipher()
        {
            _feistel = new FeistelNetwork(
                new DesKeyExpansion(),
                new DesRoundFunction());
        }

        public void SetKey(byte[] key)
        {
            if (key is null) throw new ArgumentNullException(nameof(key));
            if (key.Length != KeySizeBytes)
                throw new ArgumentException(
                    $"DES key must be exactly {KeySizeBytes} bytes, got {key.Length}.",
                    nameof(key));

            _roundKeys = _feistel.ExpandKey(key);
        }

        // IP -> F -> FP
        public byte[] EncryptBlock(byte[] block)
        {
            EnsureKeySet();
            EnsureBlockSize(block);

            // 1. IP
            byte[] permuted = BitPermutation.Permute(
                block,
                DesTables.IP,
                BitIndexing.FromMsb, BitIndexing.FromMsb,
                inStartBitNumber: 1, outStartBitNumber: 1);

            // 2. 16 раундов сети Фейстеля
            byte[] encrypted = _feistel.EncryptBlock(permuted, _roundKeys!);

            // 3. FP
            return BitPermutation.Permute(
                encrypted,
                DesTables.FP,
                BitIndexing.FromMsb, BitIndexing.FromMsb,
                inStartBitNumber: 1, outStartBitNumber: 1);
        }


        // IP -> D -> FP
        public byte[] DecryptBlock(byte[] block)
        {
            EnsureKeySet();
            EnsureBlockSize(block);

            // 1. IP
            byte[] permuted = BitPermutation.Permute(
                block,
                DesTables.IP,
                BitIndexing.FromMsb, BitIndexing.FromMsb,
                inStartBitNumber: 1, outStartBitNumber: 1);

            // 2. 16 раундов сети Фейстеля (обратный порядок ключей)
            byte[] decrypted = _feistel.DecryptBlock(permuted, _roundKeys!);

            // 3. FP
            return BitPermutation.Permute(
                decrypted,
                DesTables.FP,
                BitIndexing.FromMsb, BitIndexing.FromMsb,
                inStartBitNumber: 1, outStartBitNumber: 1);
        }

        private void EnsureKeySet()
        {
            if (_roundKeys is null)
                throw new InvalidOperationException(
                    "Key is not set. Call SetKey before EncryptBlock/DecryptBlock.");
        }

        private static void EnsureBlockSize(byte[] block)
        {
            if (block is null) throw new ArgumentNullException(nameof(block));
            if (block.Length != BlockSizeBytes)
                throw new ArgumentException(
                    $"DES block must be exactly {BlockSizeBytes} bytes, got {block.Length}.",
                    nameof(block));
        }
    }
}
