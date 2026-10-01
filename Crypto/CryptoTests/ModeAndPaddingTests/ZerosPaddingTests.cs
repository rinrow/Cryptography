using Crypto.Core.Padding;

namespace CryptoTests.ModeAndPaddingTests;

[TestClass]
public class ZerosPaddingTests
{
    [TestMethod]
    public void Pad_NonMultipleOfBlockSize_AddsZeros()
    {
        var padding = new ZerosPadding(8);
        byte[] data = { 1, 2, 3, 4, 5 };

        byte[] padded = padding.Pad(data);

        Assert.AreEqual(8, padded.Length);
        CollectionAssert.AreEqual(
            new byte[] { 1, 2, 3, 4, 5, 0, 0, 0 }, padded);
    }

    [TestMethod]
    public void Pad_MultipleOfBlockSize_DoesNotAdd()
    {
        var padding = new ZerosPadding(8);
        byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8 };

        byte[] padded = padding.Pad(data);

        Assert.AreEqual(8, padded.Length);
        CollectionAssert.AreEqual(data, padded);
    }

    [TestMethod]
    public void Unpad_RoundTrip_DataWithoutTrailingZeros()
    {
        var padding = new ZerosPadding(8);
        byte[] data = { 1, 2, 3, 4, 5 };

        byte[] padded = padding.Pad(data);
        byte[] unpadded = padding.Unpad(padded);

        CollectionAssert.AreEqual(data, unpadded);
    }

    [TestMethod]
    public void Unpad_RoundTrip_MultipleOfBlockSize()
    {
        var padding = new ZerosPadding(8);
        byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8 };

        byte[] padded = padding.Pad(data);
        byte[] unpadded = padding.Unpad(padded);

        CollectionAssert.AreEqual(data, unpadded);
    }

    [TestMethod]
    public void Unpad_TrailingZerosInData_AreLost()
    {
        // Демонстрация фундаментального свойства Zeros:
        // данные, заканчивающиеся нулями, восстанавливаются не полностью.
        var padding = new ZerosPadding(8);
        byte[] data = { 1, 2, 3, 0, 0 }; // 5 байт, два нуля в конце

        byte[] padded = padding.Pad(data);
        byte[] unpadded = padding.Unpad(padded);

        // Ожидаем потерю нулей на конце
        CollectionAssert.AreNotEqual(data, unpadded);
        CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, unpadded);
    }

    [TestMethod]
    public void Unpad_NoPadding_ReturnsDataAsIs()
    {
        var padding = new ZerosPadding(8);
        byte[] data = { 1, 2, 3, 4, 5, 6, 7, 8 };

        byte[] unpadded = padding.Unpad(data);

        CollectionAssert.AreEqual(data, unpadded);
    }
}