using System.Text;
using Crypto.Core.Context;
using Crypto.Core.Enums;
using Crypto.DES;

namespace Crypto.Tests;

[TestClass]
public class SymmetricCipherContextTests
{
    private static readonly byte[] DefaultKey =
        { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };

    private static DesCipher MakeCipher()
    {
        var des = new DesCipher();
        des.SetKey(DefaultKey);
        return des;
    }

    private static byte[] MakeIV(CipherMode mode)
    {
        // Все режимы у нас используют IV длиной = BlockSize = 8.
        return new byte[8];
    }

    private static SymmetricCipherContext MakeContext(
        CipherMode mode, PaddingMode padding, byte[]? iv = null)
    {
        var des = MakeCipher();
        return new SymmetricCipherContext(des, mode, padding, iv ?? MakeIV(mode));
    }

    // Список всех режимов (кроме ECB, которому IV не нужен).
    private static IEnumerable<CipherMode> ModesWithIV => new[]
    {
        CipherMode.CBC, CipherMode.PCBC, CipherMode.CFB,
        CipherMode.OFB, CipherMode.CTR, CipherMode.RandomDelta
    };

    private static IEnumerable<CipherMode> AllModes => new[]
    {
        CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC, CipherMode.CFB,
        CipherMode.OFB, CipherMode.CTR, CipherMode.RandomDelta
    };

    private static IEnumerable<PaddingMode> AllPaddings => new[]
    {
        PaddingMode.Pkcs7, PaddingMode.Zeros,
        PaddingMode.AnsiX923, PaddingMode.Iso10126
    };

    // ================================================================
    // 1. Матрица: режим × набивка, round-trip на случайных данных
    // ================================================================

    [DataTestMethod]
    [DynamicData(nameof(GetModePaddingCombinations), DynamicDataSourceType.Method)]
    public void RoundTrip_AllModePaddingCombinations(CipherMode mode, PaddingMode padding)
    {
        var ctx = MakeContext(mode, padding);

        // Данные длиной 100 байт (не кратно 8) — гарантированно есть padding.
        byte[] plaintext = new byte[100];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted,
            $"Round-trip failed for mode={mode}, padding={padding}");
    }

    public static IEnumerable<object[]> GetModePaddingCombinations()
    {
        foreach (var mode in AllModes)
            foreach (var padding in AllPaddings)
                yield return new object[] { mode, padding };
    }

    // ================================================================
    // 2. Разные размеры данных (для одного режима — CBC + PKCS7)
    // ================================================================

    [DataTestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(7)]
    [DataRow(8)]        // ровно блок
    [DataRow(9)]
    [DataRow(16)]       // ровно 2 блока
    [DataRow(17)]
    [DataRow(1000)]
    public void RoundTrip_VariousSizes_CbcPkcs7(int size)
    {
        var ctx = MakeContext(CipherMode.CBC, PaddingMode.Pkcs7);

        byte[] plaintext = new byte[size];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted,
            $"Round-trip failed for size={size}");
    }

    // ================================================================
    // 3. Параллельный путь (200 блоков = 1600 байт)
    // ================================================================

    [DataTestMethod]
    [DataRow(CipherMode.ECB)]
    [DataRow(CipherMode.CBC)]
    [DataRow(CipherMode.CFB)]
    [DataRow(CipherMode.CTR)]
    [DataRow(CipherMode.RandomDelta)]
    public void RoundTrip_ParallelPath_LargeData(CipherMode mode)
    {
        // 200 блоков > ParallelThreshold (16). Для ECB/CTR/RandomDelta
        // параллелится и шифрование, и дешифрование.
        // Для CBC/CFB — только дешифрование.
        var ctx = MakeContext(mode, PaddingMode.Pkcs7);

        byte[] plaintext = new byte[200 * 8];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted,
            $"Parallel round-trip failed for mode={mode}");
    }

    // ================================================================
    // 4. Детерминизм: одинаковый ключ + IV → одинаковый шифртекст
    // ================================================================

    [DataTestMethod]
    [DynamicData(nameof(GetModePaddingCombinations), DynamicDataSourceType.Method)]
    public void Encrypt_Deterministic_SameKeySameIV(CipherMode mode, PaddingMode padding)
    {
        if (padding == PaddingMode.Iso10126)
        {
            // не детерминирован
            return;
        }

        byte[] plaintext = Encoding.UTF8.GetBytes("Determinism test");

        var ctx1 = MakeContext(mode, padding);
        var ctx2 = MakeContext(mode, padding);

        byte[] c1 = ctx1.Encrypt(plaintext);
        byte[] c2 = ctx2.Encrypt(plaintext);

        CollectionAssert.AreEqual(c1, c2,
            $"Encryption must be deterministic for mode={mode}, padding={padding}");
    }

    // ================================================================
    // 5. Разные IV → разные шифртексты
    // ================================================================

    [DataTestMethod]
    [DataRow(CipherMode.CBC)]
    [DataRow(CipherMode.PCBC)]
    [DataRow(CipherMode.CFB)]
    [DataRow(CipherMode.OFB)]
    [DataRow(CipherMode.CTR)]
    [DataRow(CipherMode.RandomDelta)]
    public void Encrypt_DifferentIVs_ProduceDifferentCiphertexts(CipherMode mode)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes("IV sensitivity test");

        byte[] iv1 = new byte[8];
        byte[] iv2 = new byte[8];
        iv2[0] = 0xFF;

        var ctx1 = MakeContext(mode, PaddingMode.Pkcs7, iv1);
        var ctx2 = MakeContext(mode, PaddingMode.Pkcs7, iv2);

        byte[] c1 = ctx1.Encrypt(plaintext);
        byte[] c2 = ctx2.Encrypt(plaintext);

        CollectionAssert.AreNotEqual(c1, c2,
            $"Different IVs must produce different ciphertexts for mode={mode}");
    }

    // ================================================================
    // 6. Валидация
    // ================================================================

    [TestMethod]
    public void Ctor_NullCipher_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new SymmetricCipherContext(null!, CipherMode.ECB, PaddingMode.Pkcs7));
    }

    [TestMethod]
    public void Ctor_IvRequiredButNull_Throws()
    {
        var des = MakeCipher();

        Assert.Throws<ArgumentException>(() =>
            new SymmetricCipherContext(
                des, CipherMode.CBC, PaddingMode.Pkcs7, iv: null));
    }

    [TestMethod]
    public void Ctor_WrongIvSize_Throws()
    {
        var des = MakeCipher();
        byte[] wrongIv = new byte[7];

        Assert.Throws<ArgumentException>(() =>
            new SymmetricCipherContext(
                des, CipherMode.CBC, PaddingMode.Pkcs7, wrongIv));
    }

    [TestMethod]
    public void Encrypt_NullData_Throws()
    {
        var ctx = MakeContext(CipherMode.ECB, PaddingMode.Pkcs7);

        Assert.Throws<ArgumentNullException>(() =>
            ctx.Encrypt(null!));
    }

    [TestMethod]
    public void Decrypt_DataNotMultipleOfBlockSize_Throws()
    {
        var ctx = MakeContext(CipherMode.ECB, PaddingMode.Pkcs7);
        byte[] badData = new byte[7]; // не кратно 8

        Assert.Throws<ArgumentException>(() =>
            ctx.Decrypt(badData));
    }

    [TestMethod]
    public void Decrypt_EmptyData_Throws()
    {
        var ctx = MakeContext(CipherMode.ECB, PaddingMode.Pkcs7);

        Assert.Throws<ArgumentException>(() =>
            ctx.Decrypt(Array.Empty<byte>()));
    }

    // ================================================================
    // 7. Async-обёртки
    // ================================================================

    [TestMethod]
    public async Task EncryptAsync_DecryptAsync_RoundTrip()
    {
        var ctx = MakeContext(CipherMode.CBC, PaddingMode.Pkcs7);

        byte[] plaintext = new byte[100];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertext = await ctx.EncryptAsync(plaintext);
        byte[] decrypted = await ctx.DecryptAsync(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    // ================================================================
    // 8. Файловые операции — round-trip на разных размерах
    // ================================================================

    [DataTestMethod]
    [DataRow(0)]        // пустой файл
    [DataRow(1)]        // меньше блока
    [DataRow(7)]        // меньше блока, почти полный
    [DataRow(8)]        // ровно блок
    [DataRow(9)]        // блок + 1
    [DataRow(16)]       // ровно 2 блока
    [DataRow(1000)]     // много блоков
    [DataRow(100_001)]  // очень много блоков
    public async Task FileRoundTrip_VariousSizes(int size)
    {
        var ctx = MakeContext(CipherMode.CBC, PaddingMode.Pkcs7);

        string tempDir = Path.GetTempPath();
        string inputPath = Path.Combine(tempDir, $"crypto_in_{Guid.NewGuid():N}.bin");
        string encPath = Path.Combine(tempDir, $"crypto_enc_{Guid.NewGuid():N}.bin");
        string decPath = Path.Combine(tempDir, $"crypto_dec_{Guid.NewGuid():N}.bin");

        try
        {
            byte[] original = new byte[size];
            new Random(42).NextBytes(original);
            await File.WriteAllBytesAsync(inputPath, original);

            await ctx.EncryptFileAsync(inputPath, encPath);
            await ctx.DecryptFileAsync(encPath, decPath);

            byte[] decrypted = await File.ReadAllBytesAsync(decPath);
            CollectionAssert.AreEqual(original, decrypted,
                $"File round-trip failed for size={size}");
        }
        finally
        {
            File.Delete(inputPath);
            File.Delete(encPath);
            File.Delete(decPath);
        }
    }

    [DataTestMethod]
    [DataRow(CipherMode.CBC)]
    [DataRow(CipherMode.ECB)]
    [DataRow(CipherMode.PCBC)]
    [DataRow(CipherMode.CFB)]
    [DataRow(CipherMode.OFB)]
    [DataRow(CipherMode.CTR)]
    [DataRow(CipherMode.RandomDelta)]
    public async Task FileRoundTrip_AllModes(CipherMode mode)
    {
        var ctx = MakeContext(mode, PaddingMode.Pkcs7);

        string tempDir = Path.GetTempPath();
        string inputPath = Path.Combine(tempDir, $"crypto_in_{Guid.NewGuid():N}.bin");
        string encPath = Path.Combine(tempDir, $"crypto_enc_{Guid.NewGuid():N}.bin");
        string decPath = Path.Combine(tempDir, $"crypto_dec_{Guid.NewGuid():N}.bin");

        try
        {
            // Размер 999 — не кратен 8, не пустой, много блоков.
            byte[] original = new byte[999];
            new Random(42).NextBytes(original);
            await File.WriteAllBytesAsync(inputPath, original);

            await ctx.EncryptFileAsync(inputPath, encPath);
            await ctx.DecryptFileAsync(encPath, decPath);

            byte[] decrypted = await File.ReadAllBytesAsync(decPath);
            CollectionAssert.AreEqual(original, decrypted,
                $"File round-trip failed for mode={mode}");
        }
        finally
        {
            File.Delete(inputPath);
            File.Delete(encPath);
            File.Delete(decPath);
        }
    }

    [DataTestMethod]
    [DynamicData(nameof(GetModePaddingCombinations), DynamicDataSourceType.Method)]
    public async Task FileRoundTrip_AllModePaddingCombinations(
        CipherMode mode, PaddingMode padding)
    {
        var ctx = MakeContext(mode, padding);

        string tempDir = Path.GetTempPath();
        string inputPath = Path.Combine(tempDir, $"crypto_in_{Guid.NewGuid():N}.bin");
        string encPath = Path.Combine(tempDir, $"crypto_enc_{Guid.NewGuid():N}.bin");
        string decPath = Path.Combine(tempDir, $"crypto_dec_{Guid.NewGuid():N}.bin");

        try
        {
            // Для Zeros: данные не должны заканчиваться нулями, иначе round-trip
            // потеряет их (свойство Zeros, а не баг).
            byte[] original = new byte[100];
            new Random(42).NextBytes(original);
            if (padding == PaddingMode.Zeros)
                original[^1] = 0x42; // гарантируем ненулевой последний байт

            await File.WriteAllBytesAsync(inputPath, original);

            await ctx.EncryptFileAsync(inputPath, encPath);
            await ctx.DecryptFileAsync(encPath, decPath);

            byte[] decrypted = await File.ReadAllBytesAsync(decPath);
            CollectionAssert.AreEqual(original, decrypted,
                $"File round-trip failed for mode={mode}, padding={padding}");
        }
        finally
        {
            File.Delete(inputPath);
            File.Delete(encPath);
            File.Delete(decPath);
        }
    }

    // ================================================================
    // 9. Файловые операции: валидация
    // ================================================================

    [TestMethod]
    public async Task DecryptFileAsync_EmptyEncryptedFile_Throws()
    {
        var ctx = MakeContext(CipherMode.CBC, PaddingMode.Pkcs7);

        string tempDir = Path.GetTempPath();
        string encPath = Path.Combine(tempDir, $"crypto_enc_{Guid.NewGuid():N}.bin");
        string decPath = Path.Combine(tempDir, $"crypto_dec_{Guid.NewGuid():N}.bin");

        try
        {
            await File.WriteAllBytesAsync(encPath, Array.Empty<byte>());

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ctx.DecryptFileAsync(encPath, decPath));
        }
        finally
        {
            File.Delete(encPath);
            File.Delete(decPath);
        }
    }

    [TestMethod]
    public async Task DecryptFileAsync_SizeNotMultipleOfBlock_Throws()
    {
        var ctx = MakeContext(CipherMode.CBC, PaddingMode.Pkcs7);

        string tempDir = Path.GetTempPath();
        string encPath = Path.Combine(tempDir, $"crypto_enc_{Guid.NewGuid():N}.bin");
        string decPath = Path.Combine(tempDir, $"crypto_dec_{Guid.NewGuid():N}.bin");

        try
        {
            // 13 байт — не кратно 8
            await File.WriteAllBytesAsync(encPath, new byte[13]);

            await Assert.ThrowsAsync<InvalidDataException>(() =>
                ctx.DecryptFileAsync(encPath, decPath));
        }
        finally
        {
            File.Delete(encPath);
            File.Delete(decPath);
        }
    }

    [TestMethod]
    public async Task EncryptFileAsync_NullPaths_Throws()
    {
        var ctx = MakeContext(CipherMode.CBC, PaddingMode.Pkcs7);

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            ctx.EncryptFileAsync(null!, "out.bin"));

        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            ctx.EncryptFileAsync("in.bin", null!));
    }

    // ================================================================
    // 10. ECB без IV
    // ================================================================

    [TestMethod]
    public void Ecb_NoIVRequired_RoundTrip()
    {
        var des = MakeCipher();
        var ctx = new SymmetricCipherContext(
            des, CipherMode.ECB, PaddingMode.Pkcs7, iv: null);

        byte[] plaintext = Encoding.UTF8.GetBytes("ECB has no IV");

        byte[] ciphertext = ctx.Encrypt(plaintext);
        byte[] decrypted = ctx.Decrypt(ciphertext);

        CollectionAssert.AreEqual(plaintext, decrypted);
    }

    // ================================================================
    // 11. Демонстрация ECB-свойства: одинаковые блоки → одинаковый шифртекст
    // ================================================================

    [TestMethod]
    public void Ecb_IdenticalBlocks_ProduceIdenticalCiphertext()
    {
        var ctx = MakeContext(CipherMode.ECB, PaddingMode.Pkcs7);

        // 2 одинаковых блока
        byte[] plaintext = new byte[16];
        for (int i = 0; i < 8; i++) plaintext[i] = 0xAA;
        for (int i = 8; i < 16; i++) plaintext[i] = 0xAA;

        byte[] ciphertext = ctx.Encrypt(plaintext);

        for (int i = 0; i < 8; i++)
            Assert.AreEqual(ciphertext[i], ciphertext[8 + i],
                "ECB: одинаковые блоки → одинаковый шифртекст");
    }

    // ================================================================
    // 12. CBC-свойство: одинаковые блоки → разный шифртекст
    // ================================================================

    [TestMethod]
    public void Cbc_IdenticalBlocks_ProduceDifferentCiphertext()
    {
        var ctx = MakeContext(CipherMode.CBC, PaddingMode.Pkcs7);

        byte[] plaintext = new byte[16];
        for (int i = 0; i < 8; i++) plaintext[i] = 0xAA;
        for (int i = 8; i < 16; i++) plaintext[i] = 0xAA;

        byte[] ciphertext = ctx.Encrypt(plaintext);

        bool anyDifferent = false;
        for (int i = 0; i < 8; i++)
        {
            if (ciphertext[i] != ciphertext[8 + i])
            {
                anyDifferent = true;
                break;
            }
        }
        Assert.IsTrue(anyDifferent,
            "CBC: одинаковые блоки должны давать разные шифртексты");
    }

    [TestMethod]
    public void File_vs_Array_CBC()
    {
        var ctx = MakeContext(CipherMode.CBC, PaddingMode.Pkcs7);

        byte[] plaintext = new byte[999];
        new Random(42).NextBytes(plaintext);

        // Массив
        byte[] ciphertextArray = ctx.Encrypt(plaintext);

        // Файл
        string tempDir = Path.GetTempPath();
        string inPath = Path.Combine(tempDir, $"in_{Guid.NewGuid():N}.bin");
        string encPath = Path.Combine(tempDir, $"enc_{Guid.NewGuid():N}.bin");

        try
        {
            File.WriteAllBytes(inPath, plaintext);
            ctx.EncryptFileAsync(inPath, encPath).Wait();
            byte[] ciphertextFile = File.ReadAllBytes(encPath);

            Assert.AreEqual(ciphertextArray.Length, ciphertextFile.Length,
                "Размеры шифртекстов должны совпадать");

            for (int i = 0; i < ciphertextArray.Length; i++)
            {
                if (ciphertextArray[i] != ciphertextFile[i])
                {
                    Assert.Fail($"Расхождение на позиции {i}: array={ciphertextArray[i]}, file={ciphertextFile[i]}");
                }
            }
        }
        finally
        {
            File.Delete(inPath);
            File.Delete(encPath);
        }
    }

    [TestMethod]
    public void File_vs_Array_DECRYPT_CBC()
    {
        var ctx = MakeContext(CipherMode.CBC, PaddingMode.Pkcs7);

        byte[] plaintext = new byte[999];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertextArray = ctx.Encrypt(plaintext);

        string tempDir = Path.GetTempPath();
        string encPath = Path.Combine(tempDir, $"enc_{Guid.NewGuid():N}.bin");
        string decPath = Path.Combine(tempDir, $"dec_{Guid.NewGuid():N}.bin");

        try
        {
            File.WriteAllBytes(encPath, ciphertextArray);
            ctx.DecryptFileAsync(encPath, decPath).Wait();
            byte[] decryptedFile = File.ReadAllBytes(decPath);

            Console.WriteLine($"plaintext: {plaintext.Length}, decryptedFile: {decryptedFile.Length}");
            Console.WriteLine($"ciphertext array: {ciphertextArray.Length}");
            Console.WriteLine($"encPath size: {new FileInfo(encPath).Length}");

            CollectionAssert.AreEqual(plaintext, decryptedFile);
        }
        finally
        {
            File.Delete(encPath);
            File.Delete(decPath);
        }
    }

    [TestMethod]
    public void Array_Decrypt_CBC_FirstTwoBlocks()
    {
        var ctx = MakeContext(CipherMode.CBC, PaddingMode.Pkcs7);

        byte[] plaintext = new byte[999];
        new Random(42).NextBytes(plaintext);

        byte[] ciphertextArray = ctx.Encrypt(plaintext);
        byte[] decryptedArray = ctx.Decrypt(ciphertextArray);

        Console.WriteLine($"Plaintext[0..8]:  {BitConverter.ToString(plaintext, 0, 8)}");
        Console.WriteLine($"Decrypted[0..8]:  {BitConverter.ToString(decryptedArray, 0, 8)}");
        Console.WriteLine($"Plaintext[8..16]: {BitConverter.ToString(plaintext, 8, 8)}");
        Console.WriteLine($"Decrypted[8..16]: {BitConverter.ToString(decryptedArray, 8, 8)}");

        CollectionAssert.AreEqual(plaintext, decryptedArray);
    }
}