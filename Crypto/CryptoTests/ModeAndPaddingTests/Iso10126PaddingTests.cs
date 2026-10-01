using System.IO;
using System.Security.Cryptography;
using Crypto.Core.Padding;

namespace CryptoTests.ModeAndPaddingTests;

/// <summary>
/// Детерминированный «RNG» для тестов: возвращает байты 0xAA, 0xBB, ...
/// </summary>
internal sealed class FakeRng : RandomNumberGenerator
{
    private byte _counter;

    public override void GetBytes(byte[] data)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] = _counter++;
    }

    public override void GetBytes(Span<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] = _counter++;
    }

    public override void GetNonZeroBytes(byte[] data)
    {
        for (int i = 0; i < data.Length; i++)
            data[i] = (byte)(_counter++ | 1); // гарантируем ненулевое
    }
}

[TestClass]
public class Iso10126PaddingTests
{
    [TestMethod]
    public void Pad_NonMultipleOfBlockSize_FillsRandomAndLength()
    {
        var rng = new FakeRng();
        var padding = new Iso10126Padding(8, rng);
        byte[] data = { 1, 2, 3, 4, 5 };

        byte[] padded = padding.Pad(data);

        Assert.AreEqual(8, padded.Length);
        // Ожидаем: 1 2 3 4 5 0x00 0x01 0x03
        // FakeRng начинает с 0, потом 1
        CollectionAssert.AreEqual(
            new byte[] { 1, 2, 3, 4, 5, 0x00, 0x01, 0x03 }, padded);
    }

    [TestMethod]
    public void Pad_MultipleOfBlockSize_AddsWholeBlock()
    {
        var rng = new FakeRng();
        var padding = new Iso10126Padding(8, rng);
        byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8 };

        byte[] padded = padding.Pad(data);

        Assert.AreEqual(16, padded.Length);
        // Последний байт = 8 (BlockSize)
        Assert.AreEqual(8, padded[15]);
        // Байты 8..14 — случайные (в нашем случае 0x00..0x06)
        CollectionAssert.AreEqual(
            new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
            padded[8..15]);
    }

    [TestMethod]
    public void Unpad_RoundTrip_DataWithoutTrailingZeros()
    {
        var padding = new Iso10126Padding(8);
        byte[] data = { 1, 2, 3, 4, 5 };

        byte[] padded = padding.Pad(data);
        byte[] unpadded = padding.Unpad(padded);

        CollectionAssert.AreEqual(data, unpadded);
    }

    [TestMethod]
    public void Unpad_RoundTrip_MultipleOfBlockSize()
    {
        var padding = new Iso10126Padding(8);
        byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8 };

        byte[] padded = padding.Pad(data);
        byte[] unpadded = padding.Unpad(padded);

        CollectionAssert.AreEqual(data, unpadded);
    }

    [TestMethod]
    public void Unpad_RoundTrip_DataWithTrailingZeros()
    {
        var padding = new Iso10126Padding(8);
        byte[] data = { 1, 2, 3, 0, 0 };

        byte[] padded = padding.Pad(data);
        byte[] unpadded = padding.Unpad(padded);

        CollectionAssert.AreEqual(data, unpadded);
    }

    [TestMethod]
    public void Unpad_EmptyInput()
    {
        var padding = new Iso10126Padding(8);

        byte[] padded = padding.Pad(Array.Empty<byte>());
        Assert.AreEqual(8, padded.Length);
        Assert.AreEqual(8, padded[7]); // длина набивки

        byte[] unpadded = padding.Unpad(padded);
        Assert.AreEqual(0, unpadded.Length);
    }

    [TestMethod]
    public void Pad_ProducesDifferentOutput_OnEachCall()
    {
        // Случайные байты должны различаться между вызовами.
        var padding = new Iso10126Padding(8);
        byte[] data = { 1, 2, 3, 4, 5 };

        byte[] padded1 = padding.Pad(data);
        byte[] padded2 = padding.Pad(data);

        // Последний байт один и тот же (длина), но случайные — разные
        // (с очень высокой вероятностью)
        Assert.AreEqual(padded1[7], padded2[7]); // длина набивки

        // Проверяем, что хотя бы один из случайных байтов отличается.
        // Вероятность ложного срабатывания крайне мала (2^-16 для двух байт).
        bool anyDifferent = false;
        for (int i = 5; i < 7; i++)
        {
            if (padded1[i] != padded2[i])
            {
                anyDifferent = true;
                break;
            }
        }
        Assert.IsTrue(anyDifferent, "Случайные байты набивки должны различаться");
    }

    [TestMethod]
    public void Unpad_InvalidPaddingLength_Throws()
    {
        var padding = new Iso10126Padding(8);
        byte[] corrupted = { 1, 2, 3, 4, 5, 6, 7, 0 };

        Assert.Throws<InvalidDataException>(() =>
            padding.Unpad(corrupted));
    }

    [TestMethod]
    public void Unpad_PaddingLengthTooLarge_Throws()
    {
        var padding = new Iso10126Padding(8);
        byte[] corrupted = { 1, 2, 3, 4, 5, 6, 7, 9 };

        Assert.Throws<InvalidDataException>(() =>
            padding.Unpad(corrupted));
    }

    [TestMethod]
    public void Unpad_NotMultipleOfBlockSize_Throws()
    {
        var padding = new Iso10126Padding(8);
        byte[] corrupted = { 1, 2, 3, 4, 5 };

        Assert.Throws<InvalidDataException>(() =>
            padding.Unpad(corrupted));
    }
}