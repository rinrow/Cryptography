using Crypto.Core.Context;
using Crypto.Core.Enums;
using Crypto.Core.Interfaces;
using Crypto.DEAL;
using Crypto.DES;
using System;

namespace CryptoDemo;

class Program
{
    static void Main()
    {
        InteractiveDemo.Run();
    }
}

public static class InteractiveDemo
{
    private static readonly byte[] Key =
        { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };

    private static readonly byte[] IV = new byte[8];

    public static void Run()
    {
        string? aPath = "C:\\Users\\RinRow\\Desktop\\in.mp4";

        string? bPath = "C:\\Users\\RinRow\\Desktop\\res";

        string? cPath = "C:\\Users\\RinRow\\Desktop\\out.mp4";

        CipherMode mode;
        PaddingMode padding;
        ISymmetricCipher cipher;
        try
        {
            mode = AskMode();
            padding = AskPadding();
            cipher = AskCipher();
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Ошибка: {ex.Message}");
            return;
        }

        int blockSize = cipher switch
        {
            DesCipher => 8,
            DealCipher => 16,
            _ => throw new NotSupportedException()
        };


        byte[] iv = new byte[blockSize];
        byte[] key = new byte[blockSize];

        cipher.SetKey(key);

        var ctx = new SymmetricCipherContext(
            cipher, mode, padding, mode == CipherMode.ECB ? null : iv);

        try
        {
            // 1. Шифруем A → B
            Console.WriteLine();
            Console.WriteLine($"[1/2] Шифрование: {aPath} → {bPath}");
            ctx.EncryptFileAsync(aPath, bPath).GetAwaiter().GetResult();
            Console.WriteLine($"      Готово. Размер: {new FileInfo(bPath).Length} байт");

            // 2. Дешифруем B → C
            Console.WriteLine($"[2/2] Дешифрование: {bPath} → {cPath}");
            ctx.DecryptFileAsync(bPath, cPath).GetAwaiter().GetResult();
            Console.WriteLine($"      Готово. Размер: {new FileInfo(cPath).Length} байт");

            // 3. Проверяем round-trip
            byte[] original = File.ReadAllBytes(aPath);
            byte[] restored = File.ReadAllBytes(cPath);
            bool ok = original.AsSpan().SequenceEqual(restored);

            Console.WriteLine();
            Console.WriteLine($"Round-trip: {(ok ? "OK" : "FAIL")}");
            if (!ok)
                Console.WriteLine("ВНИМАНИЕ: расшифрованный файл не совпадает с исходным!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка: {ex.Message}");
        }
    }

    private static ISymmetricCipher AskCipher()
    {
        Console.WriteLine("Алгоритм:");
        Console.WriteLine("1. DES");
        Console.WriteLine("2. DEAL");
        Console.Write("Выбор: ");

        return Console.ReadLine() switch
        {
            "1" => new DesCipher(),
            "2" => new DealCipher(),
            _ => throw new ArgumentException("Неверный алгоритм")
        };
    }

    private static CipherMode AskMode()
    {
        Console.WriteLine();
        Console.WriteLine("Режим:");
        Console.WriteLine("1. ECB");
        Console.WriteLine("2. CBC");
        Console.WriteLine("3. PCBC");
        Console.WriteLine("4. CFB");
        Console.WriteLine("5. OFB");
        Console.WriteLine("6. CTR");
        Console.WriteLine("7. RandomDelta");
        Console.Write("Выбор: ");

        return Console.ReadLine() switch
        {
            "1" => CipherMode.ECB,
            "2" => CipherMode.CBC,
            "3" => CipherMode.PCBC,
            "4" => CipherMode.CFB,
            "5" => CipherMode.OFB,
            "6" => CipherMode.CTR,
            "7" => CipherMode.RandomDelta,
            _ => throw new ArgumentException("Неверный режим")
        };
    }

    private static PaddingMode AskPadding()
    {
        Console.WriteLine();
        Console.WriteLine("Набивка:");
        Console.WriteLine("1. Zeros");
        Console.WriteLine("2. ANSI X.923");
        Console.WriteLine("3. PKCS7");
        Console.WriteLine("4. ISO 10126");
        Console.Write("Выбор: ");

        return Console.ReadLine() switch
        {
            "1" => PaddingMode.Zeros,
            "2" => PaddingMode.AnsiX923,
            "3" => PaddingMode.Pkcs7,
            "4" => PaddingMode.Iso10126,
            _ => throw new ArgumentException("Неверная набивка")
        };
    }
}