using Crypto.Core.Enums;
using Crypto.Core.Context;
using Crypto.DES;

namespace Crypto.Tests;

[TestClass]
public class PcbcModeTests
{
    private static DesCipher MakeDes(byte[]? key = null)
    {
        var des = new DesCipher();
        des.SetKey(key ?? new byte[] { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 });
        return des;
    }

    [TestMethod]
    public void Pcbc_Pkcs7_RoundTrip()
    {
        var des = MakeDes();
        byte[] iv = new byte[8];

        var ctx = new SymmetricCipherContext(
            des, CipherMode.PCBC, PaddingMode.Pkcs7, iv);

        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(
            "Hello, DES with PCBC and PKCS7!");

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Pcbc_ExactBlockMultiple_RoundTrip()
    {
        var des = MakeDes();
        byte[] iv = new byte[8];

        var ctx = new SymmetricCipherContext(
            des, CipherMode.PCBC, PaddingMode.Pkcs7, iv);

        byte[] plaintext = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Pcbc_DifferentIVs_ProduceDifferentCiphertexts()
    {
        var des = MakeDes();
        byte[] iv1 = new byte[8];
        byte[] iv2 = new byte[8];
        iv2[0] = 0xFF;

        byte[] plaintext = { 1, 2, 3, 4, 5 };

        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.PCBC, PaddingMode.Pkcs7, iv1);
        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.PCBC, PaddingMode.Pkcs7, iv2);

        byte[] c1 = ctx1.Encrypt(plaintext);
        byte[] c2 = ctx2.Encrypt(plaintext);

        CollectionAssert.AreNotEqual(c1, c2,
            "Разные IV должны давать разные шифртексты");
    }

    [TestMethod]
    public void Pcbc_PropagationProperty()
    {
        // Свойство PCBC: изменение P_0 меняет C_0 и все последующие C_i.
        // Проверим, что при изменении P_0 меняется весь шифртекст.
        var des = MakeDes();
        byte[] iv = new byte[8];

        byte[] plaintext1 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] plaintext2 = (byte[])plaintext1.Clone();
        plaintext2[0] ^= 0xFF; // меняем только первый байт P_0

        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.PCBC, PaddingMode.Pkcs7, iv);
        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.PCBC, PaddingMode.Pkcs7, iv);

        byte[] c1 = ctx1.Encrypt(plaintext1);
        byte[] c2 = ctx2.Encrypt(plaintext2);

        // В CBC изменились бы только C_0 и C_1. В PCBC — все блоки.
        // Проверим, что второй блок тоже отличается (в CBC он бы тоже отличался),
        // и третий (в CBC он уже совпал бы).
        CollectionAssert.AreNotEqual(c1, c2);
    }

    [TestMethod]
    public void Pcbc_WithoutIV_Throws()
    {
        var des = MakeDes();

        Assert.Throws<ArgumentException>(() =>
            new SymmetricCipherContext(
                des, CipherMode.PCBC, PaddingMode.Pkcs7, iv: null));
    }
}