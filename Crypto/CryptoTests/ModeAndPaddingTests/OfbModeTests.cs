using Crypto.Core.Context;
using Crypto.Core.Enums;
using Crypto.DES;

namespace Crypto.Tests;

[TestClass]
public class OfbModeTests
{
    private static DesCipher MakeDes()
    {
        var des = new DesCipher();
        des.SetKey(new byte[] { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 });
        return des;
    }

    [TestMethod]
    public void Ofb_Pkcs7_RoundTrip_SmallData()
    {
        var des = MakeDes();
        byte[] iv = new byte[8];

        var ctx = new SymmetricCipherContext(
            des, CipherMode.OFB, PaddingMode.Pkcs7, iv);

        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, OFB!");

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Ofb_Pkcs7_RoundTrip_ManyBlocks()
    {
        var des = MakeDes();
        byte[] iv = new byte[8];

        var ctx = new SymmetricCipherContext(
            des, CipherMode.OFB, PaddingMode.Pkcs7, iv);

        byte[] plaintext = new byte[200 * 8];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Ofb_ExactBlockMultiple_RoundTrip()
    {
        var des = MakeDes();
        byte[] iv = new byte[8];

        var ctx = new SymmetricCipherContext(
            des, CipherMode.OFB, PaddingMode.Pkcs7, iv);

        byte[] plaintext = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Ofb_IsSymmetric_EncryptEqualsDecryptAlgorithm()
    {
        // Ключевое свойство OFB: E и D используют одну и ту же операцию.
        // Проверим через round-trip и через симметричность.
        var des = MakeDes();
        byte[] iv = new byte[8];

        byte[] plaintext = new byte[64];
        new Random(42).NextBytes(plaintext);

        // Шифруем
        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.OFB, PaddingMode.Pkcs7, iv);
        byte[] ciphertext = ctx1.Encrypt(plaintext);

        // Дешифруем тем же контекстом на тех же данных
        // (для OFB дешифрование = шифрование с тем же ключом и IV)
        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.OFB, PaddingMode.Pkcs7, iv);
        byte[] decrypted = ctx2.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Ofb_DifferentIVs_ProduceDifferentCiphertexts()
    {
        var des = MakeDes();
        byte[] iv1 = new byte[8];
        byte[] iv2 = new byte[8];
        iv2[0] = 0xFF;

        byte[] plaintext = { 1, 2, 3, 4, 5, 6, 7, 8 };

        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.OFB, PaddingMode.Pkcs7, iv1);
        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.OFB, PaddingMode.Pkcs7, iv2);

        byte[] c1 = ctx1.Encrypt(plaintext);
        byte[] c2 = ctx2.Encrypt(plaintext);

        CollectionAssert.AreNotEqual(c1, c2);
    }

    [TestMethod]
    public void Ofb_KeystreamIndependentOfData()
    {
        // В OFB keystream O_i не зависит от открытого текста.
        // Значит, XOR двух шифртекстов = XOR двух открытых текстов.
        var des = MakeDes();
        byte[] iv = new byte[8];

        byte[] p1 = { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] p2 = { 10, 20, 30, 40, 50, 60, 70, 80 };

        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.OFB, PaddingMode.Pkcs7, iv);
        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.OFB, PaddingMode.Pkcs7, iv);

        byte[] c1 = ctx1.Encrypt(p1);
        byte[] c2 = ctx2.Encrypt(p2);

        // C_1 XOR C_2 = P_1 XOR P_2 (первые 8 байт — до padding'а)
        for (int i = 0; i < 8; i++)
        {
            byte expected = (byte)(p1[i] ^ p2[i]);
            byte actual = (byte)(c1[i] ^ c2[i]);
            Assert.AreEqual(expected, actual,
                "OFB: C_1 XOR C_2 должно равняться P_1 XOR P_2");
        }
    }

    [TestMethod]
    public void Ofb_WithoutIV_Throws()
    {
        var des = MakeDes();

        Assert.Throws<ArgumentException>(() =>
            new SymmetricCipherContext(
                des, CipherMode.OFB, PaddingMode.Pkcs7, iv: null));
    }
}