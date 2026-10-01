using Crypto.Feistel;
using Crypto.Core.Interfaces;

namespace Crypto.DEAL;

/// <summary>
/// Алгоритм DEAL на базе сети Фейстеля (задание 3).
/// Раундовая функция — DES через DesAsRoundFunctionAdapter.
///
/// Блок: 16 байт (128 бит).
/// Ключ: 16 байт (128 бит).
/// Раундов: 6.
///
/// ВАЖНО: DEAL — это сеть Фейстеля с раундовой функцией DES.
/// IP/FP от DES здесь НЕ применяются — они внутри F.
/// </summary>
public sealed class DealCipher : ISymmetricCipher
{
    public const int BlockSizeBytes = 16;
    public const int KeySizeBytes = 16;

    private readonly FeistelNetwork _feistel;
    private byte[][]? _roundKeys;

    public DealCipher()
    {
        _feistel = new FeistelNetwork(
            new DealKeyExpansion(),
            new DesAsRoundFunctionAdapter());
    }

    public void SetKey(byte[] key)
    {
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (key.Length != KeySizeBytes)
            throw new ArgumentException(
                $"DEAL key must be {KeySizeBytes} bytes, got {key.Length}.", nameof(key));

        _roundKeys = _feistel.ExpandKey(key);
    }

    public byte[] EncryptBlock(byte[] block)
    {
        EnsureKeySet();
        EnsureBlockSize(block);
        return _feistel.EncryptBlock(block, _roundKeys!);
    }

    public byte[] DecryptBlock(byte[] block)
    {
        EnsureKeySet();
        EnsureBlockSize(block);
        return _feistel.DecryptBlock(block, _roundKeys!);
    }

    private void EnsureKeySet()
    {
        if (_roundKeys is null)
            throw new InvalidOperationException(
                "Key is not set. Call SetKey before EncryptBlock/DecryptBlock.");
    }

    private static void EnsureBlockSize(byte[] block)
    {
        if (block is null) throw new ArgumentNullException(nameof(block));
        if (block.Length != BlockSizeBytes)
            throw new ArgumentException(
                $"DEAL block must be {BlockSizeBytes} bytes, got {block.Length}.",
                nameof(block));
    }
}