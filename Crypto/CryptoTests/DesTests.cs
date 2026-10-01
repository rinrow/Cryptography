using Crypto.DES;
using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Tests;

[TestClass]
public class DesTests
{
    [TestMethod]
    public void DesRoundFunction_KnownVector()
    {
        var f = new DesRoundFunction();

        byte[] r0 = { 0xF0, 0xAA, 0xF0, 0xAA };
        byte[] k1 = { 0x1B, 0x02, 0xEF, 0xFC, 0x70, 0x72 };

        byte[] result = f.Transform(r0, k1);

        CollectionAssert.AreEqual(
            new byte[] { 0x23, 0x4A, 0xA9, 0xBB },
            result);
    }

    [TestMethod]
    public void DesCipher_KnownVector()
    {
        var des = new DesCipher();

        byte[] key = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
        byte[] plaintext = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        byte[] expected = { 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };

        des.SetKey(key);

        byte[] ciphertext = des.EncryptBlock(plaintext);
        CollectionAssert.AreEqual(expected, ciphertext, "Шифрование DES");

        byte[] decrypted = des.DecryptBlock(ciphertext);
        CollectionAssert.AreEqual(plaintext, decrypted, "Дешифрование DES");
    }

    [TestMethod]
    public void DesCipher_Random()
    {
        var des = new DesCipher();
        var rng = new Random(12345); // фиксированный seed для воспроизводимости

        for (int iter = 0; iter < 100; iter++)
        {
            byte[] key = new byte[8];
            byte[] plaintext = new byte[8];
            rng.NextBytes(key);
            rng.NextBytes(plaintext);

            des.SetKey(key);

            byte[] ciphertext = des.EncryptBlock(plaintext);
            byte[] decrypted = des.DecryptBlock(ciphertext);

            CollectionAssert.AreEqual(plaintext, decrypted,
                $"Round-trip failed for key={Convert.ToHexString(key)}, " +
                $"plaintext={Convert.ToHexString(plaintext)}");
        }
    }

    [TestMethod]
    public void DesCipher_WeakKey_EncryptEqualsDecrypt()
    {
        var des = new DesCipher();

        // Один из слабых ключей DES: 0x0101010101010101
        byte[] weakKey = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
        byte[] plaintext = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

        des.SetKey(weakKey);

        byte[] encrypted = des.EncryptBlock(plaintext);
        byte[] decrypted = des.DecryptBlock(plaintext);

        CollectionAssert.AreEqual(encrypted, decrypted,
            "Для слабого ключа шифрование и дешифрование должны совпадать");
    }

    [TestMethod]
    public void DesCipher_WrongKeySize_Throws()
    {
        var des = new DesCipher();

        Assert.Throws<ArgumentException>(() =>
        des.SetKey(new byte[7]));
    }

    [TestMethod]
    public void DesCipher_WrongBlockSize_Throws()
    {
        var des = new DesCipher();
        des.SetKey(new byte[8]);
        Assert.Throws<ArgumentException>(() =>
        des.EncryptBlock(new byte[7]));
    }

    [TestMethod]
    public void DesCipher_EncryptWithoutKey_Throws()
    {
        var des = new DesCipher();
        Assert.Throws<InvalidOperationException>(() =>
        des.EncryptBlock(new byte[8]));
    }
}
