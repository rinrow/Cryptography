using Crypto.Core.Context;
using Crypto.DEAL;
using Crypto.Core.Enums;

namespace CryptoTests;

[TestClass]
public class DealTests
{
    [TestMethod]
    public void Deal_RoundTrip_SingleBlock()
    {
        var deal = new DealCipher();
        deal.SetKey(new byte[16]);

        byte[] plaintext = new byte[16];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertext = deal.EncryptBlock(plaintext);
        byte[] decrypted = deal.DecryptBlock(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Deal_RoundTrip_Context_CBC()
    {
        var deal = new DealCipher();
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        deal.SetKey(key);
        var ctx = new SymmetricCipherContext(
            deal, CipherMode.CBC, PaddingMode.Pkcs7, iv);

        byte[] plaintext = new byte[100];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }
}
