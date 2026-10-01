namespace Crypto.Core.Padding;

/// <summary>
/// Набивка нулями (Zeros).
///
/// Байты набивки — нули. Длина набивки — от 1 до BlockSize.
///
/// ВАЖНО: если данные уже кратны BlockSize, набивка НЕ добавляется.
/// Иначе невозможно было бы отличить набивку от данных, заканчивающихся нулями.
///
/// Следствие: Unpad не может однозначно восстановить исходные данные,
/// если они заканчивались нулями. Это фундаментальное свойство Zeros,
/// а не баг реализации. Используйте, когда:
///   - длина исходных данных известна заранее (например, хранится отдельно),
///   - данные заведомо не заканчиваются нулями.
///
/// Для надёжного round-trip используйте PKCS7, ANSI X.923 или ISO 10126.
/// </summary>
public sealed class ZerosPadding : IPadding
{
    public ZerosPadding(int blockSize)
    {
        if (blockSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(blockSize));

        BlockSize = blockSize;
    }

    public int BlockSize { get; }

    public byte[] Pad(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        int remainder = data.Length % BlockSize;
        if (remainder == 0)
        {
            // Уже кратно — набивка не нужна.
            return (byte[])data.Clone();
        }

        int padLength = BlockSize - remainder;
        byte[] result = new byte[data.Length + padLength];
        Buffer.BlockCopy(data, 0, result, 0, data.Length);
        // Остальные байты уже 0 по умолчанию.

        return result;
    }

    public byte[] Unpad(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        if (data.Length == 0 || data.Length % BlockSize != 0)
            throw new ArgumentException(
                $"Padded data length must be a positive multiple of {BlockSize}.",
                nameof(data));

        // Идём с конца, пока не встретим ненулевой байт.
        // Всё, что после него — набивка.
        //
        // ВНИМАНИЕ: если исходные данные заканчивались нулями,
        // они тоже будут отрезаны. Это свойство Zeros.
        int end = data.Length;
        while (end > 0 && data[end - 1] == 0)
            end--;

        byte[] result = new byte[end];
        Buffer.BlockCopy(data, 0, result, 0, end);
        return result;
    }
}