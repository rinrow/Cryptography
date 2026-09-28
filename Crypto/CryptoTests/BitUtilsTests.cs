using Crypto.Core.BitOperations;

namespace Crypto.Tests;

[TestClass]
public class BitUtilsTests
{
    // ---------- FromLsb, startBitNumber = 0 ----------

    [TestMethod]
    public void GetBit_FromLsb0_LsbIsBit0()
    {
        byte[] data = { 0x81 }; // 1000_0001

        Assert.AreEqual(1, BitUtils.GetBit(data, 0, BitIndexing.FromLsb, 0)); // LSB
        Assert.AreEqual(1, BitUtils.GetBit(data, 7, BitIndexing.FromLsb, 0)); // MSB
        Assert.AreEqual(0, BitUtils.GetBit(data, 1, BitIndexing.FromLsb, 0));
    }

    // ---------- FromLsb, startBitNumber = 1 ----------

    [TestMethod]
    public void GetBit_FromLsb1_LsbIsBit1()
    {
        byte[] data = { 0x81 };

        Assert.AreEqual(1, BitUtils.GetBit(data, 1, BitIndexing.FromLsb, 1)); // LSB
        Assert.AreEqual(1, BitUtils.GetBit(data, 8, BitIndexing.FromLsb, 1)); // MSB
    }

    // ---------- FromMsb, startBitNumber = 0 ----------

    [TestMethod]
    public void GetBit_FromMsb0_MsbOfFirstByteIsBit0()
    {
        byte[] data = { 0x81 }; // 1000_0001

        Assert.AreEqual(1, BitUtils.GetBit(data, 0, BitIndexing.FromMsb, 0)); // MSB
        Assert.AreEqual(1, BitUtils.GetBit(data, 7, BitIndexing.FromMsb, 0)); // LSB
        Assert.AreEqual(0, BitUtils.GetBit(data, 6, BitIndexing.FromMsb, 0));
    }

    [TestMethod]
    public void GetBit_FromMsb0_BytesAreNotReversed()
    {
        // Ключевая проверка: при FromMsb байты идут в прямом порядке,
        // разворачиваются только биты ВНУТРИ каждого байта.
        byte[] data = { 0x80, 0x01 }; // 1000_0000 0000_0001

        // Бит 0 = MSB первого байта = 1
        Assert.AreEqual(1, BitUtils.GetBit(data, 0, BitIndexing.FromMsb, 0));
        // Бит 7 = LSB первого байта = 0
        Assert.AreEqual(0, BitUtils.GetBit(data, 7, BitIndexing.FromMsb, 0));
        // Бит 8 = MSB второго байта = 0
        Assert.AreEqual(0, BitUtils.GetBit(data, 8, BitIndexing.FromMsb, 0));
        // Бит 15 = LSB второго байта = 1
        Assert.AreEqual(1, BitUtils.GetBit(data, 15, BitIndexing.FromMsb, 0));
    }

    // ---------- FromMsb, startBitNumber = 1 (FIPS DES) ----------

    [TestMethod]
    public void GetBit_FromMsb1_FipsConvention()
    {
        // 0xEF = 1110_1111
        byte[] data = { 0x00, 0xEF };

        // Бит 1 = MSB первого байта = 0
        Assert.AreEqual(0, BitUtils.GetBit(data, 1, BitIndexing.FromMsb, 1));
        // Бит 8 = LSB первого байта = 0
        Assert.AreEqual(0, BitUtils.GetBit(data, 8, BitIndexing.FromMsb, 1));
        // Бит 9 = MSB второго байта = 1
        Assert.AreEqual(1, BitUtils.GetBit(data, 9, BitIndexing.FromMsb, 1));
        // Бит 10 = второй бит второго байта = 1
        Assert.AreEqual(1, BitUtils.GetBit(data, 10, BitIndexing.FromMsb, 1));
        // Бит 12 = четвёртый бит второго байта = 0
        Assert.AreEqual(0, BitUtils.GetBit(data, 12, BitIndexing.FromMsb, 1));
        // Бит 16 = LSB второго байта = 1
        Assert.AreEqual(1, BitUtils.GetBit(data, 16, BitIndexing.FromMsb, 1));
    }

    // ---------- SetBit ----------

    [TestMethod]
    public void SetBit_FromLsb0_SetsCorrectBit()
    {
        byte[] data = { 0x00 };
        BitUtils.SetBit(data, 0, 1, BitIndexing.FromLsb, 0);
        Assert.AreEqual(0x01, data[0]);

        BitUtils.SetBit(data, 7, 1, BitIndexing.FromLsb, 0);
        Assert.AreEqual(0x81, data[0]);

        BitUtils.SetBit(data, 0, 0, BitIndexing.FromLsb, 0);
        Assert.AreEqual(0x80, data[0]);
    }

    [TestMethod]
    public void SetBit_FromMsb0_SetsCorrectBit()
    {
        byte[] data = { 0x00 };
        BitUtils.SetBit(data, 0, 1, BitIndexing.FromMsb, 0);
        Assert.AreEqual(0x80, data[0]);

        BitUtils.SetBit(data, 7, 1, BitIndexing.FromMsb, 0);
        Assert.AreEqual(0x81, data[0]);

        BitUtils.SetBit(data, 0, 0, BitIndexing.FromMsb, 0);
        Assert.AreEqual(0x01, data[0]);
    }

    // ---------- Границы ----------

    [TestMethod]
    public void GetBit_IndexOutOfRange_Throws()
    {
        byte[] data = { 0xFF };
        Assert.Throws<ArgumentOutOfRangeException>(() => BitUtils.GetBit(data, 8, BitIndexing.FromLsb, 0));
    }

    [TestMethod]
    public void GetBit_NegativeIndex_Throws()
    {
        byte[] data = { 0xFF };
        Assert.Throws<ArgumentOutOfRangeException>(() => BitUtils.GetBit(data, -1, BitIndexing.FromLsb, 0));
    }
}