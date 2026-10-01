using Crypto.Core.Context;
using Crypto.DES;
using Crypto.Core.Enums;

namespace CryptoTests.ModeAndPaddingTests
{
    [TestClass]
    public class ContextTest
    {
        [TestMethod]
        public void Ecb_ParallelAndSequential_SameResult()
        {
            // Проверяем, что параллельный и последовательный пути
            // дают одинаковый результат для ECB.
            var des = new DesCipher();
            des.SetKey(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });

            var ctx = new SymmetricCipherContext(des, CipherMode.ECB, PaddingMode.Pkcs7);

            // 200 блоков → заведомо больше ParallelThreshold
            byte[] plaintext = new byte[200 * 8];
            new Random(42).NextBytes(plaintext);

            byte[] ciphertext = ctx.Encrypt(plaintext);
            byte[] decrypted = ctx.Decrypt(ciphertext);

            CollectionAssert.AreEqual(plaintext, decrypted);
        }

        [TestMethod]
        public void Cbc_SequentialAndParallelDecrypt_SameResult()
        {
            var des = new DesCipher();
            des.SetKey(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });

            byte[] iv = new byte[8];
            var ctx = new SymmetricCipherContext(
                des, CipherMode.CBC, PaddingMode.Pkcs7, iv);

            byte[] plaintext = new byte[200 * 8];
            new Random(42).NextBytes(plaintext);

            byte[] ciphertext = ctx.Encrypt(plaintext);   // последовательно
            byte[] decrypted = ctx.Decrypt(ciphertext);   // параллельно

            CollectionAssert.AreEqual(plaintext, decrypted);
        }
    }
}
