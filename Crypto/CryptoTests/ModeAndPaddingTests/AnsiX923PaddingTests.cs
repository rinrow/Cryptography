using System.IO;
using Crypto.Core.Padding;

namespace CryptoTests.ModeAndPaddingTests;

[TestClass]
public class AnsiX923PaddingTests
{
    [TestMethod]
    public void Pad_NonMultipleOfBlockSize_AddsZerosAndLength()
    {
        var padding = new AnsiX923Padding(8);
        byte[] data = { 1, 2, 3, 4, 5 };

        byte[] padded = padding.Pad(data);

        Assert.AreEqual(8, padded.Length);
        CollectionAssert.AreEqual(
            new byte[] { 1, 2, 3, 4, 5, 0, 0, 3 }, padded);
    }

    [TestMethod]
    public void Pad_MultipleOfBlockSize_AddsWholeBlock()
    {
        var padding = new AnsiX923Padding(8);
        byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8 };

        byte[] padded = padding.Pad(data);

        Assert.AreEqual(16, padded.Length);
        CollectionAssert.AreEqual(
            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 8 },
            padded);
    }

    [TestMethod]
    public void Unpad_RoundTrip_DataWithoutTrailingZeros()
    {
        var padding = new AnsiX923Padding(8);
        byte[] data = { 1, 2, 3, 4, 5 };

        byte[] padded = padding.Pad(data);
        byte[] unpadded = padding.Unpad(padded);

        CollectionAssert.AreEqual(data, unpadded);
    }

    [TestMethod]
    public void Unpad_RoundTrip_MultipleOfBlockSize()
    {
        var padding = new AnsiX923Padding(8);
        byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8 };

        byte[] padded = padding.Pad(data);
        byte[] unpadded = padding.Unpad(padded);

        CollectionAssert.AreEqual(data, unpadded);
    }

    [TestMethod]
    public void Unpad_RoundTrip_DataWithTrailingZeros()
    {
        var padding = new AnsiX923Padding(8);
        byte[] data = { 1, 2, 3, 0, 0 };

        byte[] padded = padding.Pad(data);
        byte[] unpadded = padding.Unpad(padded);

        CollectionAssert.AreEqual(data, unpadded);
    }

    [TestMethod]
    public void Unpad_EmptyInput()
    {
        var padding = new AnsiX923Padding(8);

        byte[] padded = padding.Pad(Array.Empty<byte>());
        Assert.AreEqual(8, padded.Length);
        CollectionAssert.AreEqual(
            new byte[] { 0, 0, 0, 0, 0, 0, 0, 8 }, padded);

        byte[] unpadded = padding.Unpad(padded);
        Assert.AreEqual(0, unpadded.Length);
    }

    [TestMethod]
    public void Unpad_InvalidPaddingLength_Throws()
    {
        var padding = new AnsiX923Padding(8);
        // Последний байт = 0 — недопустимо (длина набивки ∈ [1, 8])
        byte[] corrupted = { 1, 2, 3, 4, 5, 6, 7, 0 };

        Assert.Throws<InvalidDataException>(() =>
            padding.Unpad(corrupted));
    }

    [TestMethod]
    public void Unpad_PaddingLengthTooLarge_Throws()
    {
        var padding = new AnsiX923Padding(8);
        // Последний байт = 9 — больше BlockSize
        byte[] corrupted = { 1, 2, 3, 4, 5, 6, 7, 9 };

        Assert.Throws<InvalidDataException>(() =>
            padding.Unpad(corrupted));
    }

    [TestMethod]
    public void Unpad_NonZeroByteInPaddingArea_Throws()
    {
        var padding = new AnsiX923Padding(8);
        // Последний байт = 3, но набивка должна быть { 0, 0, 3 }
        // Здесь набивка { 0, 5, 3 } — байт 5 ненулевой
        byte[] corrupted = { 1, 2, 3, 4, 5, 0, 5, 3 };

        Assert.Throws<InvalidDataException>(() =>
            padding.Unpad(corrupted));
    }

    [TestMethod]
    public void Unpad_NotMultipleOfBlockSize_Throws()
    {
        var padding = new AnsiX923Padding(8);
        byte[] corrupted = { 1, 2, 3, 4, 5 }; // 5 байт, не кратно 8

        Assert.Throws<InvalidDataException>(() =>
            padding.Unpad(corrupted));
    }
}