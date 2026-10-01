using Crypto.Core.BitOperations;

namespace Crypto.Tests;

[TestClass]
public class BitPermutationTests
{
    // ================================================================
    // 1. Тождественные перестановки
    // ================================================================

    [TestMethod]
    public void Identity_FromLsb0_SingleByte()
    {
        byte[] input = { 0b1011_0010 }; // 0xB2
        int[] pBlock = { 0, 1, 2, 3, 4, 5, 6, 7 };

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromLsb, BitIndexing.FromLsb,
            0, 0);

        CollectionAssert.AreEqual(input, result);
    }

    [TestMethod]
    public void Identity_FromMsb0_SingleByte()
    {
        byte[] input = { 0b1011_0010 };
        int[] pBlock = { 0, 1, 2, 3, 4, 5, 6, 7 };

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromMsb, BitIndexing.FromMsb,
            0, 0);

        CollectionAssert.AreEqual(input, result);
    }

    [TestMethod]
    public void Identity_FromLsb0_TwoBytes()
    {
        byte[] input = { 0xAB, 0xCD };
        int[] pBlock = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromLsb, BitIndexing.FromLsb,
            0, 0);

        CollectionAssert.AreEqual(input, result);
    }

    // ================================================================
    // 2. Разворот битов внутри байта
    // ================================================================

    [TestMethod]
    public void ReverseBits_FromLsb0_NonSymmetric()
    {
        // 0x80 → 0x01
        byte[] input = { 0x80 };
        int[] pBlock = { 7, 6, 5, 4, 3, 2, 1, 0 };

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromLsb, BitIndexing.FromLsb,
            0, 0);

        CollectionAssert.AreEqual(new byte[] { 0x01 }, result);
    }

    [TestMethod]
    public void ReverseBits_FromMsb0_NonSymmetric()
    {
        // 0x80 (MSB=1) → 0x01 (LSB=1)
        byte[] input = { 0x80 };
        int[] pBlock = { 7, 6, 5, 4, 3, 2, 1, 0 };

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromMsb, BitIndexing.FromMsb,
            0, 0);

        CollectionAssert.AreEqual(new byte[] { 0x01 }, result);
    }

    // ================================================================
    // 3. Нумерация с 1
    // ================================================================

    [TestMethod]
    public void Identity_FromLsb1_SingleByte()
    {
        byte[] input = { 0xB2 };
        int[] pBlock = { 1, 2, 3, 4, 5, 6, 7, 8 };

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromLsb, BitIndexing.FromLsb,
            1, 1);

        CollectionAssert.AreEqual(input, result);
    }

    [TestMethod]
    public void Identity_FromMsb1_SingleByte()
    {
        byte[] input = { 0xB2 };
        int[] pBlock = { 1, 2, 3, 4, 5, 6, 7, 8 };

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromMsb, BitIndexing.FromMsb,
            1, 1);

        CollectionAssert.AreEqual(input, result);
    }

    // ================================================================
    // 4. Ключевой тест: байты НЕ разворачиваются при FromMsb
    // ================================================================

    [TestMethod]
    public void FromMsb0_BytesAreNotReversed()
    {
        // Вход: 0x80 0x00
        // При правильной трактовке FromMsb бит 0 = MSB первого байта = 1.
        // Если бы байты разворачивались — был бы бит из 0x00 = 0.
        byte[] input = { 0x80, 0x00 };
        int[] pBlock = { 0 }; // берём бит 0 входа → бит 0 выхода

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromMsb, BitIndexing.FromMsb,
            0, 0);

        Assert.AreEqual(0x80, result[0],
            "FromMsb не должен разворачивать байты — бит 0 это MSB первого байта");
    }

    [TestMethod]
    public void FromMsb0_SecondByteAccessibleViaBit8()
    {
        // Вход: 0x00 0x80
        // Бит 8 = MSB второго байта = 1
        byte[] input = { 0x00, 0x80 };
        int[] pBlock = { 8 };

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromMsb, BitIndexing.FromMsb,
            0, 0);

        Assert.AreEqual(0x80, result[0],
            "Бит 8 при FromMsb — это MSB второго байта (байты не разворачиваются)");
    }

    // ================================================================
    // 5. Эталонный тест: IP-перестановка DES (FIPS PUB 46-3)
    // ================================================================

    // Таблица IP — нумерация с 1, от MSB первого байта.
    private static readonly int[] IP_TABLE =
    {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    [TestMethod]
    public void DesInitialPermutation_KnownVector()
    {
        // Классический пример:
        // вход  = 0x0123456789ABCDEF
        // после IP = 0xCC00CCFFF0AAF0AA
        byte[] input = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
        byte[] expected = { 0xCC, 0x00, 0xCC, 0xFF, 0xF0, 0xAA, 0xF0, 0xAA };

        byte[] result = BitPermutation.Permute(
            input, IP_TABLE,
            BitIndexing.FromMsb, BitIndexing.FromMsb,
            1, 1);

        CollectionAssert.AreEqual(expected, result,
            "IP-перестановка DES должна давать CC00CCFFF0AAF0AA");
    }

    [TestMethod]
    public void PBlockLengthNotMultipleOf8_OutputRoundedUp()
    {
        byte[] input = { 0xFF, 0xFF };
        int[] pBlock = { 0, 1, 2, 3, 4 }; // 5 бит → 1 байт на выходе

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromLsb, BitIndexing.FromLsb,
            0, 0);

        Assert.AreEqual(1, result.Length, "5 бит должны упаковаться в 1 байт");
        Assert.AreEqual(0x1F, result[0]);
    }

    // ================================================================
    // 8. Смешанные режимы входа/выхода
    // ================================================================

    [TestMethod]
    public void MixedIndexing_InLsb_OutMsb()
    {
        // Вход:  0x80 = 1000_0000
        // FromLsb: бит 7 = 1, бит 0 = 0
        // P-блок: { 7 } → берём бит 7 входа (=1) → бит 0 выхода
        // FromMsb на выходе: бит 0 = MSB → выставляем MSB
        byte[] input = { 0x80 };
        int[] pBlock = { 7 };

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromLsb, BitIndexing.FromMsb,
            0, 0);

        Assert.AreEqual(0x80, result[0]); // MSB выставлен
    }

    [TestMethod]
    public void MixedIndexing_InMsb_OutLsb()
    {
        // Вход:  0x80 = 1000_0000
        // FromMsb: бит 0 = MSB = 1
        // P-блок: { 0 } → берём бит 0 входа (=1) → бит 0 выхода
        // FromLsb на выходе: бит 0 = LSB → выставляем LSB
        byte[] input = { 0x80 };
        int[] pBlock = { 0 };

        byte[] result = BitPermutation.Permute(
            input, pBlock,
            BitIndexing.FromMsb, BitIndexing.FromLsb,
            0, 0);

        Assert.AreEqual(0x01, result[0]); // LSB выставлен
    }
}