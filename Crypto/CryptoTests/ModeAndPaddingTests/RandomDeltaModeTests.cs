using Crypto.Core.Context;
using Crypto.Core.Enums;
using Crypto.DES;

namespace Crypto.Tests;

[TestClass]
public class RandomDeltaModeTests
{
    private static DesCipher MakeDes()
    {
        var des = new DesCipher();
        des.SetKey(new byte[] { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 });
        return des;
    }

    [TestMethod]
    public void RandomDelta_Pkcs7_RoundTrip_SmallData()
    {
        var des = MakeDes();
        byte[] ivFull = new byte[8]; // 4 байта IV + 4 байта delta

        var ctx = new SymmetricCipherContext(
            des, CipherMode.RandomDelta, PaddingMode.Pkcs7, ivFull);

        byte[] plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, Random Delta!");

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void RandomDelta_Pkcs7_RoundTrip_ManyBlocks_Parallel()
    {
        var des = MakeDes();
        byte[] ivFull = new byte[8];

        var ctx = new SymmetricCipherContext(
            des, CipherMode.RandomDelta, PaddingMode.Pkcs7, ivFull);

        byte[] plaintext = new byte[200 * 8];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void RandomDelta_IsSymmetric()
    {
        var des = MakeDes();
        byte[] ivFull = new byte[8];
        new Random(42).NextBytes(ivFull);

        byte[] plaintext = new byte[64];
        new Random(43).NextBytes(plaintext);

        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.RandomDelta, PaddingMode.Pkcs7, ivFull);
        byte[] ciphertext = ctx1.Encrypt(plaintext);

        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.RandomDelta, PaddingMode.Pkcs7, ivFull);
        byte[] decrypted = ctx2.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void RandomDelta_KeystreamIndependentOfData()
    {
        // C_1 XOR C_2 = P_1 XOR P_2 (как в CTR)
        var des = MakeDes();
        byte[] ivFull = new byte[8];

        byte[] p1 = { 1, 2, 3, 4, 5, 6, 7, 8 };
        byte[] p2 = { 10, 20, 30, 40, 50, 60, 70, 80 };

        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.RandomDelta, PaddingMode.Pkcs7, ivFull);
        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.RandomDelta, PaddingMode.Pkcs7, ivFull);

        byte[] c1 = ctx1.Encrypt(p1);
        byte[] c2 = ctx2.Encrypt(p2);

        for (int i = 0; i < 8; i++)
        {
            byte expected = (byte)(p1[i] ^ p2[i]);
            byte actual = (byte)(c1[i] ^ c2[i]);
            Assert.AreEqual(expected, actual);
        }
    }

    [TestMethod]
    public void RandomDelta_DifferentDelta_ProduceDifferentCiphertexts()
    {
        var des = MakeDes();
        byte[] ivFull1 = new byte[8];
        byte[] ivFull2 = new byte[8];
        ivFull2[7] = 0x01; // меняем delta (правая половина)

        byte[] plaintext = { 1, 2, 3, 4, 5, 6, 7, 8 };

        var ctx1 = new SymmetricCipherContext(
            des, CipherMode.RandomDelta, PaddingMode.Pkcs7, ivFull1);
        var ctx2 = new SymmetricCipherContext(
            des, CipherMode.RandomDelta, PaddingMode.Pkcs7, ivFull2);

        byte[] c1 = ctx1.Encrypt(plaintext);
        byte[] c2 = ctx2.Encrypt(plaintext);

        CollectionAssert.AreNotEqual(c1, c2);
    }

    [TestMethod]
    public void RandomDelta_OverflowAllowed()
    {
        // IV_full с delta, близкой к 2^32, и IV около 2^32.
        // counter_i = IV + delta * i должен wrap-around, не бросать.
        var des = MakeDes();
        byte[] ivFull = new byte[8];
        for (int i = 0; i < 4; i++) ivFull[i] = 0xFF;       // IV = 0xFFFFFFFF
        for (int i = 4; i < 8; i++) ivFull[i] = 0xFF;       // delta = 0xFFFFFFFF

        var ctx = new SymmetricCipherContext(
            des, CipherMode.RandomDelta, PaddingMode.Pkcs7, ivFull);

        byte[] plaintext = new byte[64]; // 8 блоков — counter_i выйдет за 2^32
        new Random(42).NextBytes(plaintext);

        // Не должно бросать.
        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    [TestMethod]
    public void RandomDelta_WithoutIV_Throws()
    {
        var des = MakeDes();

        Assert.Throws<ArgumentException>(() =>
            new SymmetricCipherContext(
                des, CipherMode.RandomDelta, PaddingMode.Pkcs7, iv: null));
    }
}