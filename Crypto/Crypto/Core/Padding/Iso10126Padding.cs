using System.Security.Cryptography;

namespace Crypto.Core.Padding;

/// <summary>
/// Набивка ISO 10126.
///
/// Схема: data || random * (padLength - 1) || padLength
/// где padLength ∈ [1, BlockSize].
///
/// Если данные кратны BlockSize, добавляется целый блок набивки.
///
/// Отличие от ANSI X.923: байты набивки (кроме последнего) — случайные,
/// а не нули. Это усложняет анализ набивки при атаках типа padding oracle.
///
/// Отличие от PKCS7: байты набивки не равны padLength.
/// </summary>
public sealed class Iso10126Padding : IPadding
{
    private readonly RandomNumberGenerator _rng;

    public Iso10126Padding(int blockSize)
        : this(blockSize, RandomNumberGenerator.Create())
    {
    }

    /// <summary>
    /// Конструктор с явной передачей RNG — для тестов
    /// (можно подсунуть детерминированный генератор).
    /// </summary>
    public Iso10126Padding(int blockSize, RandomNumberGenerator rng)
    {
        if (blockSize <= 0 || blockSize > 255)
            throw new ArgumentOutOfRangeException(
                nameof(blockSize),
                "Block size must be in range 1..255 for ISO 10126.");

        BlockSize = blockSize;
        _rng = rng ?? throw new ArgumentNullException(nameof(rng));
    }

    public int BlockSize { get; }

    public byte[] Pad(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        int padLength = BlockSize - (data.Length % BlockSize);
        // padLength ∈ [1, BlockSize].

        byte[] result = new byte[data.Length + padLength];
        Buffer.BlockCopy(data, 0, result, 0, data.Length);

        // Заполняем байты набивки случайными значениями.
        // Последний байт — длина набивки.
        int paddingStart = data.Length;
        int randomBytesCount = padLength - 1;

        if (randomBytesCount > 0)
        {
            byte[] random = new byte[randomBytesCount];
            _rng.GetBytes(random);
            Buffer.BlockCopy(random, 0, result, paddingStart, randomBytesCount);
        }

        result[^1] = (byte)padLength;

        return result;
    }

    public byte[] Unpad(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        if (data.Length == 0 || data.Length % BlockSize != 0)
            throw new InvalidDataException(
                $"Padded data length must be a positive multiple of {BlockSize}.");

        byte padLength = data[^1];
        if (padLength == 0 || padLength > BlockSize)
            throw new InvalidDataException(
                $"Invalid ISO 10126 padding length: {padLength}.");

        // В отличие от ANSI X.923, байты набивки случайные — проверить их нельзя.
        // Единственная проверка — корректность длины в последнем байте.

        byte[] result = new byte[data.Length - padLength];
        Buffer.BlockCopy(data, 0, result, 0, result.Length);
        return result;
    }
}