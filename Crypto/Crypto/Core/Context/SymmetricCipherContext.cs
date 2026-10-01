using Crypto.Core.Enums;
using Crypto.Core.Interfaces;
using Crypto.Core.Modes;
using Crypto.Core.Padding;

namespace Crypto.Core.Context;

/// <summary>
/// Контекст выполнения симметричного криптографического алгоритма.
///
/// Объединяет:
///   - блочный шифр (ISymmetricCipher),
///   - режим шифрования (IBlockCipherMode),
///   - режим набивки (IPadding).
///
/// Предоставляет методы шифрования/дешифрования массивов байтов
/// и файлов. Где возможно — распараллеливает вычисления.
/// </summary>
public sealed class SymmetricCipherContext
{
    /// <summary>
    /// Минимальное количество блоков, при котором включается параллелизм.
    /// Меньше — накладные расходы Parallel.For не окупаются.
    /// </summary>
    private const int ParallelThreshold = 16;

    private readonly ISymmetricCipher _cipher;
    private readonly IBlockCipherMode _mode;
    private readonly IPadding _padding;
    private readonly byte[]? _iv;

    public SymmetricCipherContext(
        ISymmetricCipher cipher,
        CipherMode mode,
        PaddingMode padding,
        byte[]? iv = null,
        params object[] extraParams)
    {
        _cipher = cipher ?? throw new ArgumentNullException(nameof(cipher));

        int blockSize = GetBlockSize(cipher);

        _mode = CreateMode(mode, blockSize, extraParams);
        _padding = CreatePadding(padding, blockSize);

        if (_mode.RequiresIV)
        {
            if (iv is null)
                throw new ArgumentException(
                    $"Mode {mode} requires IV.", nameof(iv));
            if (iv.Length != blockSize)
                throw new ArgumentException(
                    $"IV must be exactly {blockSize} bytes, got {iv.Length}.",
                    nameof(iv));

            _mode.SetIV(iv);
            _iv = (byte[])iv.Clone();
        }
        else
        {
            _iv = iv is null ? null : (byte[])iv.Clone();
        }
    }

    // ==================================================================
    // Шифрование
    // ==================================================================

    /// <summary>
    /// Шифрует данные.
    /// </summary>
    public byte[] Encrypt(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        byte[] padded = _padding.Pad(data);
        int blockSize = _mode.BlockSize;
        int blockCount = padded.Length / blockSize;
        byte[] result = new byte[padded.Length];

        if (_mode.CanParallelizeEncryption && blockCount >= ParallelThreshold)
            EncryptParallel(padded, result, blockSize, blockCount);
        else
            EncryptSequential(padded, result, blockSize, blockCount);

        return result;
    }

    /// <summary>
    /// Асинхронно шифрует данные.
    /// </summary>
    public Task<byte[]> EncryptAsync(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        // Выносим в пул потоков, чтобы не блокировать вызывающий поток.
        return Task.Run(() => Encrypt(data));
    }

    private void EncryptSequential(byte[] padded, byte[] result, int blockSize, int blockCount)
    {
        var state = new CipherState
        {
            Counter = 0
        };

        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = GetBlock(padded, i, blockSize);
            byte[] encrypted = _mode.EncryptBlock(_cipher, block, state);
            WriteBlock(result, i, blockSize, encrypted);

            state.Counter++;
            // PreviousCipher / PreviousPlain обновляет сам режим.
        }
    }

    private void EncryptParallel(byte[] padded, byte[] result, int blockSize, int blockCount)
    {
        Parallel.For(0, blockCount, i =>
        {
            // Для параллельного шифрования применимы только ECB и CTR.
            // В обоих случаях PreviousCipher не нужен: ECB его игнорирует,
            // CTR использует Counter.
            var state = new CipherState
            {
                Counter = i
            };

            byte[] block = GetBlock(padded, i, blockSize);
            byte[] encrypted = _mode.EncryptBlock(_cipher, block, state);
            WriteBlock(result, i, blockSize, encrypted);
        });
    }

    // ==================================================================
    // Дешифрование
    // ==================================================================

    /// <summary>
    /// Дешифрует данные.
    /// </summary>
    public byte[] Decrypt(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        int blockSize = _mode.BlockSize;
        if (data.Length == 0 || data.Length % blockSize != 0)
            throw new ArgumentException(
                $"Encrypted data length must be a multiple of {blockSize}.",
                nameof(data));

        int blockCount = data.Length / blockSize;
        byte[] result = new byte[data.Length];

        if (_mode.CanParallelizeDecryption && blockCount >= ParallelThreshold)
            DecryptParallel(data, result, blockSize, blockCount);
        else
            DecryptSequential(data, result, blockSize, blockCount);

        return _padding.Unpad(result);
    }

    /// <summary>
    /// Асинхронно дешифрует данные.
    /// </summary>
    public Task<byte[]> DecryptAsync(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        return Task.Run(() => Decrypt(data));
    }

    private void DecryptSequential(byte[] data, byte[] result, int blockSize, int blockCount)
    {
        var state = new CipherState
        {
            Counter = 0
        };

        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = GetBlock(data, i, blockSize);
            byte[] decrypted = _mode.DecryptBlock(_cipher, block, state);
            WriteBlock(result, i, blockSize, decrypted);

            state.Counter++;
        }
    }

    private void DecryptParallel(byte[] data, byte[] result, int blockSize, int blockCount)
    {
        Parallel.For(0, blockCount, i =>
        {
            // Ключевая идея: каждый поток получает СВОЙ CipherState
            // с правильным PreviousCipher = C_{i-1}.
            //
            // Для CBC/CFB/ECB это ровно то, что нужно.
            // Для CTR PreviousCipher игнорируется, важен Counter.
            var state = new CipherState
            {
                Counter = i,
                PreviousCipher = i == 0
                    ? _iv
                    : GetBlock(data, i - 1, blockSize)
            };

            byte[] block = GetBlock(data, i, blockSize);
            byte[] decrypted = _mode.DecryptBlock(_cipher, block, state);
            WriteBlock(result, i, blockSize, decrypted);
        });
    }

    // ==================================================================
    // Работа с файлами
    // ==================================================================

    /// <summary>
    /// Асинхронно шифрует файл.
    /// Результат записывается в <paramref name="outputPath"/>.
    /// </summary>
    public async Task EncryptFileAsync(string inputPath, string outputPath)
    {
        if (inputPath is null) throw new ArgumentNullException(nameof(inputPath));
        if (outputPath is null) throw new ArgumentNullException(nameof(outputPath));

        int blockSize = _mode.BlockSize;

        await using var input = new FileStream(
            inputPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: blockSize * 16, useAsync: true);

        await using var output = new FileStream(
            outputPath, FileMode.Create, FileAccess.Write, FileShare.None,
            bufferSize: blockSize * 16, useAsync: true);

        var state = new CipherState { Counter = 0 };

        byte[] current = new byte[blockSize];
        byte[] next = new byte[blockSize];

        int currentLen = await ReadFullBlockAsync(input, current, blockSize)
            .ConfigureAwait(false);

        if (0 < currentLen && currentLen < blockSize)
        {
            byte[] tail = new byte[currentLen];
            Buffer.BlockCopy(current, 0, tail, 0, currentLen);
            var res = Encrypt(tail);
            await output.WriteAsync(res, 0, res.Length).ConfigureAwait(false);
            return;
        }

        while (currentLen == blockSize)
        {
            // Пробуем прочитать следующий блок, чтобы понять, последний ли текущий.
            int nextLen = await ReadFullBlockAsync(input, next, blockSize)
                .ConfigureAwait(false);

            if (nextLen == blockSize)
            {
                // Текущий блок — не последний. Шифруем как есть.
                byte[] encrypted = _mode.EncryptBlock(_cipher, current, state);
                await output.WriteAsync(encrypted, 0, blockSize).ConfigureAwait(false);

                state.Counter++;

                // Сдвигаем буферы.
                (current, next) = (next, current);
                currentLen = nextLen;
            }
            else
            {
                // Текущий блок — последний. nextLen ∈ [0, blockSize).
                // Собираем "хвост": current + next[0..nextLen].
                byte[] tail = new byte[blockSize + nextLen];
                Buffer.BlockCopy(current, 0, tail, 0, blockSize);
                Buffer.BlockCopy(next, 0, tail, blockSize, nextLen);

                // Применяем набивку ко всему хвосту.
                byte[] paddedTail = _padding.Pad(tail);

                // Шифруем и пишем все блоки хвоста.
                for (int offset = 0; offset < paddedTail.Length; offset += blockSize)
                {
                    byte[] block = new byte[blockSize];
                    Buffer.BlockCopy(paddedTail, offset, block, 0, blockSize);

                    byte[] encrypted = _mode.EncryptBlock(_cipher, block, state);
                    await output.WriteAsync(encrypted, 0, blockSize).ConfigureAwait(false);

                    state.Counter++;
                }

                return; // готово
            }
        }

        // Сюда попадаем, только если файл пустой (currentLen == 0).
        // Тогда набивка — это один блок.
        if (currentLen == 0)
        {
            byte[] paddedTail = _padding.Pad(Array.Empty<byte>());
            for (int offset = 0; offset < paddedTail.Length; offset += blockSize)
            {
                byte[] block = new byte[blockSize];
                Buffer.BlockCopy(paddedTail, offset, block, 0, blockSize);

                byte[] encrypted = _mode.EncryptBlock(_cipher, block, state);
                await output.WriteAsync(encrypted, 0, blockSize).ConfigureAwait(false);

                state.Counter++;
            }
        }
    }

    /// <summary>
    /// Асинхронно дешифрует файл.
    /// </summary>
    public async Task DecryptFileAsync(string inputPath, string outputPath)
    {
        if (inputPath is null) throw new ArgumentNullException(nameof(inputPath));
        if (outputPath is null) throw new ArgumentNullException(nameof(outputPath));

        int blockSize = _mode.BlockSize;

        await using var input = new FileStream(
            inputPath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: blockSize * 16, useAsync: true);

        await using var output = new FileStream(
            outputPath, FileMode.Create, FileAccess.Write, FileShare.None,
            bufferSize: blockSize * 16, useAsync: true);

        var state = new CipherState { Counter = 0, PreviousCipher = _iv };

        byte[] current = new byte[blockSize];
        byte[] next = new byte[blockSize];

        int currentLen = await ReadFullBlockAsync(input, current, blockSize)
            .ConfigureAwait(false);

        if (currentLen == 0)
            throw new InvalidDataException("Encrypted file is empty.");

        if (currentLen != blockSize)
            throw new InvalidDataException(
                "Encrypted file size must be a multiple of the block size.");

        int iter = 0;
        while (true)
        {
            int nextLen = await ReadFullBlockAsync(input, next, blockSize)
                .ConfigureAwait(false);

            if (nextLen == blockSize)
            {
                // Текущий блок — не последний. Расшифровываем и пишем.
                byte[] decrypted = _mode.DecryptBlock(_cipher, current, state);
                
                await output.WriteAsync(decrypted, 0, blockSize).ConfigureAwait(false);

                state.Counter++;
                (current, next) = (next, current);
            }
            else
            {
                // Текущий блок — последний. nextLen должен быть 0,
                // иначе файл повреждён (длина не кратна blockSize).
                if (nextLen != 0)
                    throw new InvalidDataException(
                        "Encrypted file size must be a multiple of the block size.");
                
                byte[] decryptedLast = _mode.DecryptBlock(_cipher, current, state);

                // Снимаем набивку с последнего блока.
                // _padding.Unpad работает с массивом, длина которого кратна BlockSize,
                // поэтому передаём один блок.
                byte[] unpadded = _padding.Unpad(decryptedLast);

                await output.WriteAsync(unpadded, 0, unpadded.Length).ConfigureAwait(false);

                return;
            }
            iter++;
        }
    }

    // ==================================================================
    // Вспомогательные методы
    // ==================================================================

    /// <summary>
    /// Читает из потока до <paramref name="count"/> байт или до конца файла.
    /// Возвращает фактически прочитанное количество байт.
    /// </summary>
    private static async Task<int> ReadFullBlockAsync(
        Stream stream, byte[] buffer, int count)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = await stream.ReadAsync(
                buffer, totalRead, count - totalRead).ConfigureAwait(false);
            if (read == 0) break;   // конец файла
            totalRead += read;
        }
        return totalRead;
    }

    private static byte[] GetBlock(byte[] source, int blockIndex, int blockSize)
    {
        byte[] block = new byte[blockSize];
        Buffer.BlockCopy(source, blockIndex * blockSize, block, 0, blockSize);
        return block;
    }

    private static void WriteBlock(byte[] destination, int blockIndex, int blockSize, byte[] block)
    {
        Buffer.BlockCopy(block, 0, destination, blockIndex * blockSize, blockSize);
    }

    // ==================================================================
    // Фабрики
    // ==================================================================

    private static int GetBlockSize(ISymmetricCipher cipher)
    {
        return cipher switch
        {
            DES.DesCipher => DES.DesCipher.BlockSizeBytes,
            DEAL.DealCipher => DEAL.DealCipher.BlockSizeBytes,
            _ => throw new NotSupportedException(
                $"Unknown cipher type: {cipher.GetType().Name}")
        };
    }

    private static IBlockCipherMode CreateMode(
        CipherMode mode, int blockSize, object[] extraParams)
    {
        return mode switch
        {
            CipherMode.ECB => new EcbMode(blockSize),
            CipherMode.CBC => new CbcMode(blockSize),
            CipherMode.PCBC => new PcbcMode(blockSize),
            CipherMode.CFB => new CfbMode(blockSize),
            CipherMode.OFB => new OfbMode(blockSize),
            CipherMode.CTR => new CtrMode(blockSize),
            CipherMode.RandomDelta => new RandomDeltaMode(blockSize),
            _ => throw new NotImplementedException($"Mode {mode}")
        };
    }

    private static IPadding CreatePadding(PaddingMode padding, int blockSize)
    {
        return padding switch
        {
            PaddingMode.Pkcs7 => new Pkcs7Padding(blockSize),
            PaddingMode.Zeros => new ZerosPadding(blockSize),
            PaddingMode.AnsiX923 => new AnsiX923Padding(blockSize),
            PaddingMode.Iso10126 => new Iso10126Padding(blockSize),
            _ => throw new NotImplementedException($"Padding {padding}")
        };
    }
}