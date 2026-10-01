using Crypto.Core.BitOperations;

namespace Crypto.Tests;

[TestClass]
public class BitUtilsTests
{
    // ================================================================
    // 1. Один байт — проверяем оба направления внутри байта
    // ================================================================

    [TestMethod]
    public void GetBit_FromLsb0_SingleByte()
    {
        // 0x81 = 1000_0001
        // FromLsb0: индекс 0 = LSB, индекс 7 = MSB
        byte[] data = { 0x81 };

        Assert.AreEqual(1, BitUtils.GetBit(data, 0, BitIndexing.FromLsb, 0)); // LSB
        Assert.AreEqual(1, BitUtils.GetBit(data, 7, BitIndexing.FromLsb, 0)); // MSB
        Assert.AreEqual(0, BitUtils.GetBit(data, 1, BitIndexing.FromLsb, 0));
    }

    [TestMethod]
    public void GetBit_FromMsb0_SingleByte()
    {
        // 0x81 = 1000_0001
        // FromMsb0: индекс 0 = MSB, индекс 7 = LSB
        byte[] data = { 0x81 };

        Assert.AreEqual(1, BitUtils.GetBit(data, 0, BitIndexing.FromMsb, 0)); // MSB
        Assert.AreEqual(1, BitUtils.GetBit(data, 7, BitIndexing.FromMsb, 0)); // LSB
        Assert.AreEqual(0, BitUtils.GetBit(data, 6, BitIndexing.FromMsb, 0));
    }

    [TestMethod]
    public void GetBit_FromLsb1_SingleByte()
    {
        // Нумерация с 1: биты 1..8
        byte[] data = { 0x81 };

        Assert.AreEqual(1, BitUtils.GetBit(data, 1, BitIndexing.FromLsb, 1)); // LSB
        Assert.AreEqual(1, BitUtils.GetBit(data, 8, BitIndexing.FromLsb, 1)); // MSB
    }

    [TestMethod]
    public void GetBit_FromMsb1_SingleByte()
    {
        byte[] data = { 0x81 };

        Assert.AreEqual(1, BitUtils.GetBit(data, 1, BitIndexing.FromMsb, 1)); // MSB
        Assert.AreEqual(1, BitUtils.GetBit(data, 8, BitIndexing.FromMsb, 1)); // LSB
    }

    // ================================================================
    // 2. Два байта — ключевой тест порядка байтов
    // ================================================================

    [TestMethod]
    public void GetBit_FromLsb0_TwoBytes_BytesAreReversed()
    {
        // data = { 0xA5, 0x3C }
        //   байт 0 = 1010_0101
        //   байт 1 = 0011_1100
        //
        // По системе преподавателя:
        //   логический индекс 0..7  → байт 1 (последний физически)
        //   логический индекс 8..15 → байт 0 (первый физически)
        byte[] data = { 0xA5, 0x3C };

        // индекс 0 = LSB байта 1 (0x3C) = 0
        Assert.AreEqual(0, BitUtils.GetBit(data, 0, BitIndexing.FromLsb, 0));
        //// индекс 2 = бит 2 байта 1 = 1
        //Assert.AreEqual(1, BitUtils.GetBit(data, 2, BitIndexing.FromLsb, 0));
        //// индекс 3 = бит 3 байта 1 = 1
        //Assert.AreEqual(1, BitUtils.GetBit(data, 3, BitIndexing.FromLsb, 0));
        //// индекс 6 = бит 6 байта 1 = 0
        //Assert.AreEqual(0, BitUtils.GetBit(data, 6, BitIndexing.FromLsb, 0));
        //// индекс 7 = MSB байта 1 = 0
        //Assert.AreEqual(0, BitUtils.GetBit(data, 7, BitIndexing.FromLsb, 0));

        //// индекс 8 = LSB байта 0 (0xA5) = 1
        //Assert.AreEqual(1, BitUtils.GetBit(data, 8, BitIndexing.FromLsb, 0));
        //// индекс 10 = бит 2 байта 0 = 1
        //Assert.AreEqual(1, BitUtils.GetBit(data, 10, BitIndexing.FromLsb, 0));
        //// индекс 13 = бит 5 байта 0 = 1
        //Assert.AreEqual(1, BitUtils.GetBit(data, 13, BitIndexing.FromLsb, 0));
        //// индекс 15 = MSB байта 0 = 1
        //Assert.AreEqual(1, BitUtils.GetBit(data, 15, BitIndexing.FromLsb, 0));
    }

    [TestMethod]
    public void GetBit_FromMsb0_TwoBytes_BytesAreReversed()
    {
        // data = { 0xA5, 0x3C }
        //   байт 0 = 1010_0101
        //   байт 1 = 0011_1100
        //
        // FromMsb: индекс 0 = MSB ПЕРВОГО байта (байт 0).
        // Байты идут в прямом порядке, биты внутри — MSB → LSB.
        byte[] data = { 0xA5, 0x3C };

        // Первый байт: логические индексы 0..7
        Assert.AreEqual(1, BitUtils.GetBit(data, 0, BitIndexing.FromMsb, 0)); // MSB байта 0
        Assert.AreEqual(0, BitUtils.GetBit(data, 1, BitIndexing.FromMsb, 0));
        Assert.AreEqual(1, BitUtils.GetBit(data, 2, BitIndexing.FromMsb, 0));
        Assert.AreEqual(1, BitUtils.GetBit(data, 5, BitIndexing.FromMsb, 0));
        Assert.AreEqual(0, BitUtils.GetBit(data, 6, BitIndexing.FromMsb, 0));
        Assert.AreEqual(1, BitUtils.GetBit(data, 7, BitIndexing.FromMsb, 0)); // LSB байта 0

        // Второй байт: логические индексы 8..15
        Assert.AreEqual(0, BitUtils.GetBit(data, 8, BitIndexing.FromMsb, 0));  // MSB байта 1
        Assert.AreEqual(0, BitUtils.GetBit(data, 9, BitIndexing.FromMsb, 0));
        Assert.AreEqual(1, BitUtils.GetBit(data, 10, BitIndexing.FromMsb, 0));
        Assert.AreEqual(0, BitUtils.GetBit(data, 14, BitIndexing.FromMsb, 0));
        Assert.AreEqual(0, BitUtils.GetBit(data, 15, BitIndexing.FromMsb, 0)); // LSB байта 1
    }

    // ================================================================
    // 3. SetBit
    // ================================================================

    [TestMethod]
    public void SetBit_FromLsb0_SingleByte()
    {
        byte[] data = { 0x00 };

        BitUtils.SetBit(data, 0, 1, BitIndexing.FromLsb, 0);
        Assert.AreEqual(0x01, data[0]); // LSB

        BitUtils.SetBit(data, 7, 1, BitIndexing.FromLsb, 0);
        Assert.AreEqual(0x81, data[0]); // + MSB

        BitUtils.SetBit(data, 0, 0, BitIndexing.FromLsb, 0);
        Assert.AreEqual(0x80, data[0]); // - LSB
    }

    [TestMethod]
    public void SetBit_FromMsb0_SingleByte()
    {
        byte[] data = { 0x00 };

        BitUtils.SetBit(data, 0, 1, BitIndexing.FromMsb, 0);
        Assert.AreEqual(0x80, data[0]); // MSB

        BitUtils.SetBit(data, 7, 1, BitIndexing.FromMsb, 0);
        Assert.AreEqual(0x81, data[0]); // + LSB

        BitUtils.SetBit(data, 0, 0, BitIndexing.FromMsb, 0);
        Assert.AreEqual(0x01, data[0]); // - MSB
    }

    [TestMethod]
    public void SetBit_TwoBytes_BytesAreReversed()
    {
        // Логический индекс 0 → LSB последнего байта массива.
        byte[] data = { 0x00, 0x00 };

        BitUtils.SetBit(data, 0, 1, BitIndexing.FromLsb, 0);
        // Ожидаем: LSB последнего байта = 0x01
        CollectionAssert.AreEqual(new byte[] { 0x00, 0x01 }, data);

        BitUtils.SetBit(data, 8, 1, BitIndexing.FromLsb, 0);
        // Логический индекс 8 → LSB первого байта
        CollectionAssert.AreEqual(new byte[] { 0x01, 0x01 }, data);
    }

    // ================================================================
    // 4. Round-trip: SetBit → GetBit
    // ================================================================

    [TestMethod]
    public void SetThenGet_RoundTrip_AllIndices()
    {
        byte[] data = new byte[4]; // 32 бита

        for (int i = 0; i < 32; i++)
            BitUtils.SetBit(data, i, 1, BitIndexing.FromLsb, 0);

        for (int i = 0; i < 32; i++)
            Assert.AreEqual(1, BitUtils.GetBit(data, i, BitIndexing.FromLsb, 0),
                $"Бит {i} должен быть установлен");

        Assert.AreEqual(0xFF, data[0]);
        Assert.AreEqual(0xFF, data[1]);
        Assert.AreEqual(0xFF, data[2]);
        Assert.AreEqual(0xFF, data[3]);
    }

    // ================================================================
    // 5. Границы
    // ================================================================

    [TestMethod]
    public void GetBit_IndexOutOfRange_Throws()
    {
        byte[] data = { 0xFF };
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        BitUtils.GetBit(data, 8, BitIndexing.FromLsb, 0));
    }

    [TestMethod]
    public void GetBit_NegativeIndex_Throws()
    {
        byte[] data = { 0xFF };
        Assert.Throws<ArgumentOutOfRangeException>(() =>
        BitUtils.GetBit(data, -1, BitIndexing.FromLsb, 0));
    }

    [TestMethod]
    public void GetBit_InvalidStartBitNumber_Throws()
    {
        byte[] data = { 0xFF };
        Assert.Throws<ArgumentException>(() =>
        BitUtils.GetBit(data, 0, BitIndexing.FromLsb, 2));
    }
}