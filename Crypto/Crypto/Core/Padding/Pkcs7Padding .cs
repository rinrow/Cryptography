namespace Crypto.Core.Padding;

/// <summary>
/// Набивка PKCS#7 (RFC 5652, раздел 6.3).
///
/// Все байты набивки равны её длине.
/// Длина набивки — от 1 до BlockSize.
/// Если данные уже кратны BlockSize, добавляется целый блок набивки.
///
/// Пример для BlockSize = 8:
///   данные длиной 5 → добавляем 3 байта [0x03, 0x03, 0x03]
///   данные длиной 8 → добавляем 8 байт [0x08, 0x08, ..., 0x08]
/// </summary>
public sealed class Pkcs7Padding : IPadding
{
    public Pkcs7Padding(int blockSize)
    {
        if (blockSize <= 0 || blockSize > 255)
            throw new ArgumentOutOfRangeException(
                nameof(blockSize),
                "Block size must be in range 1..255 for PKCS7.");

        BlockSize = blockSize;
    }

    public int BlockSize { get; }

    public byte[] Pad(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        int padLength = BlockSize - (data.Length % BlockSize);
        // padLength ∈ [1, BlockSize]. Если data.Length кратен BlockSize,
        // padLength = BlockSize → добавляется целый блок.

        byte[] result = new byte[data.Length + padLength];
        Buffer.BlockCopy(data, 0, result, 0, data.Length);

        byte padByte = (byte)padLength;
        for (int i = data.Length; i < result.Length; i++)
            result[i] = padByte;

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
                $"Invalid PKCS7 padding length: {padLength}.");

        // Проверяем, что все последние padLength байт равны padLength.
        for (int i = data.Length - padLength; i < data.Length; i++)
            if (data[i] != padLength)
                throw new InvalidDataException("Invalid PKCS7 padding bytes.");

        byte[] result = new byte[data.Length - padLength];
        Buffer.BlockCopy(data, 0, result, 0, result.Length);
        return result;
    }
}