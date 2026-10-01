using Crypto.Core.Context;
using Crypto.Core.Enums;
using Crypto.DES;

namespace CryptoTests.ModeAndPaddingTests;

[TestClass]
public class SymmetricCipherContextEcbTests
{
    [TestMethod]
    public void Ecb_Pkcs7_RoundTrip()
    {
        var des = new DesCipher();
        des.SetKey(new byte[] { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 });

        var ctx = new SymmetricCipherContext(
            des, CipherMode.ECB, PaddingMode.Pkcs7);

        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes(
            "Hello, DES with ECB and PKCS7!");

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Ecb_Pkcs7_ExactBlockMultiple()
    {
        var des = new DesCipher();
        des.SetKey(new byte[8]);

        var ctx = new SymmetricCipherContext(
            des, CipherMode.ECB, PaddingMode.Pkcs7);

        // Ровно 8 байт — PKCS7 добавит целый блок набивки
        byte[] plaintext = { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] ciphertext = ctx.Encrypt(plaintext);

        Assert.AreEqual(16, ciphertext.Length, "PKCS7 должен добавить целый блок");

        byte[] decrypted = ctx.Decrypt(ciphertext);
        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Ecb_Pkcs7_EmptyInput()
    {
        var des = new DesCipher();
        des.SetKey(new byte[8]);

        var ctx = new SymmetricCipherContext(
            des, CipherMode.ECB, PaddingMode.Pkcs7);

        byte[] plaintext = Array.Empty<byte>();
        byte[] ciphertext = ctx.Encrypt(plaintext);

        Assert.AreEqual(8, ciphertext.Length, "PKCS7 добавит блок набивки");

        byte[] decrypted = ctx.Decrypt(ciphertext);
        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void Ecb_DeterministicForSameBlocks()
    {
        // ECB: одинаковые блоки открытого текста → одинаковые блоки шифртекста.
        // Это свойство режима, полезно проверить.
        var des = new DesCipher();
        des.SetKey(new byte[8]);

        var ctx = new SymmetricCipherContext(
            des, CipherMode.ECB, PaddingMode.Pkcs7);

        byte[] plaintext = new byte[16];
        for (int i = 0; i < 8; i++) plaintext[i] = 0xAA;
        for (int i = 8; i < 16; i++) plaintext[i] = 0xAA; // тот же блок

        byte[] ciphertext = ctx.Encrypt(plaintext);

        // Первые 8 байт шифртекста должны совпадать со вторыми 8 байтами
        for (int i = 0; i < 8; i++)
            Assert.AreEqual(ciphertext[i], ciphertext[8 + i],
                "ECB: одинаковые блоки → одинаковый шифртекст");
    }
}