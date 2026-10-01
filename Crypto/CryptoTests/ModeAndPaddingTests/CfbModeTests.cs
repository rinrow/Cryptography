using Crypto.Core.Context;
using Crypto.Core.Enums;
using Crypto.DES;

namespace Crypto.Tests;

[TestClass]
public class CfbModeTests
{
    private static DesCipher MakeDes()
    {
        var des = new DesCipher();
        des.SetKey(new byte[] { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 });
        return des;
    }

    [TestMethod]
    public void Cfb_Pkcs7_RoundTrip_SmallData()
    {
        var des = MakeDes();
        byte[] iv = new byte[8];

        var ctx = new SymmetricCipherContext(
            des, CipherMode.CFB, PaddingMode.Pkcs7, iv);

        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, CFB!");

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Cfb_Pkcs7_RoundTrip_ManyBlocks()
    {
        var des = MakeDes();
        byte[] iv = new byte[8];

        var ctx = new SymmetricCipherContext(
            des, CipherMode.CFB, PaddingMode.Pkcs7, iv);

        byte[] plaintext = new byte[200 * 8];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Cfb_ExactBlockMultiple_RoundTrip()
    {
        var des = MakeDes();
        byte[] iv = new byte[8];

        var ctx = new SymmetricCipherContext(
            des, CipherMode.CFB, PaddingMode.Pkcs7, iv);

        byte[] plaintext = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Cfb_DifferentIVs_ProduceDifferentCiphertexts()
    {
        var des = MakeDes();
        byte[] iv1 = new byte[8];
        byte[] iv2 = new byte[8];
        iv2[0] = 0xFF;

        byte[] plaintext = { 1, 2, 3, 4, 5, 6, 7, 8 };

        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.CFB, PaddingMode.Pkcs7, iv1);
        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.CFB, PaddingMode.Pkcs7, iv2);

        byte[] c1 = ctx1.Encrypt(plaintext);
        byte[] c2 = ctx2.Encrypt(plaintext);

        CollectionAssert.AreNotEqual(c1, c2,
            "Разные IV должны давать разные шифртексты");
    }

    [TestMethod]
    public void Cfb_FirstBlockCiphertext_IndependentOfLaterBlocks()
    {
        // В CFB: C_0 = P_0 XOR E(IV). Значит, C_0 не зависит от P_1.
        var des = MakeDes();
        byte[] iv = new byte[8];

        byte[] p1 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] p2 = (byte[])p1.Clone();
        p2[8] ^= 0xFF; // меняем только второй блок

        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.CFB, PaddingMode.Pkcs7, iv);
        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.CFB, PaddingMode.Pkcs7, iv);

        byte[] c1 = ctx1.Encrypt(p1);
        byte[] c2 = ctx2.Encrypt(p2);

        for (int i = 0; i < 8; i++)
            Assert.AreEqual(c1[i], c2[i],
                "CFB: C_0 не должен зависеть от P_1");
    }

    [TestMethod]
    public void Cfb_ParallelDecrypt_MatchesSequential()
    {
        // Проверяем, что параллельное дешифрование даёт тот же результат,
        // что и последовательное.
        var des = MakeDes();
        byte[] iv = new byte[8];

        byte[] plaintext = new byte[200 * 8];
        new Random(42).NextBytes(plaintext);

        // Шифруем последовательно
        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.CFB, PaddingMode.Pkcs7, iv);
        byte[] ciphertext = ctx1.Encrypt(plaintext);

        // Дешифруем — должно быть параллельно (200 блоков > threshold)
        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.CFB, PaddingMode.Pkcs7, iv);
        byte[] decrypted = ctx2.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Cfb_WithoutIV_Throws()
    {
        var des = MakeDes();

        Assert.Throws<ArgumentException>(() =>
            new SymmetricCipherContext(
                des, CipherMode.CFB, PaddingMode.Pkcs7, iv: null));
    }
}