using System.IO;

namespace Crypto.Core.Padding;

/// <summary>
/// Набивка ANSI X.923.
///
/// Схема: data || 0x00 * (padLength - 1) || padLength
/// где padLength ∈ [1, BlockSize].
///
/// Если данные кратны BlockSize, добавляется целый блок набивки:
///   padLength = BlockSize → data || 0x00 * (BlockSize - 1) || BlockSize
///
/// Отличие от PKCS7: байты набивки — нули, а не значение padLength.
/// Отличие от Zeros: последний байт кодирует длину, что делает
/// Unpad однозначным даже для данных, заканчивающихся нулями.
/// </summary>
public sealed class AnsiX923Padding : IPadding
{
    public AnsiX923Padding(int blockSize)
    {
        if (blockSize <= 0 || blockSize > 255)
            throw new ArgumentOutOfRangeException(
                nameof(blockSize),
                "Block size must be in range 1..255 for ANSI X.923.");

        BlockSize = blockSize;
    }

    public int BlockSize { get; }

    public byte[] Pad(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        int padLength = BlockSize - (data.Length % BlockSize);
        // padLength ∈ [1, BlockSize]. Если длина кратна — добавляем целый блок.

        byte[] result = new byte[data.Length + padLength];
        Buffer.BlockCopy(data, 0, result, 0, data.Length);

        // Нули в середине набивки уже там (массив инициализирован нулями).
        // Осталось записать длину в последний байт.
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
                $"Invalid ANSI X.923 padding length: {padLength}.");

        // Проверяем, что все байты набивки, кроме последнего, равны нулю.
        int paddingStart = data.Length - padLength;
        for (int i = paddingStart; i < data.Length - 1; i++)
        {
            if (data[i] != 0)
                throw new InvalidDataException(
                    "Invalid ANSI X.923 padding: non-zero byte in padding area.");
        }

        byte[] result = new byte[data.Length - padLength];
        Buffer.BlockCopy(data, 0, result, 0, result.Length);
        return result;
    }
}