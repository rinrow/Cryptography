using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Core.Interfaces
{
    /// <summary>
    /// Описание функционала по выполнению шифрования и дешифрования
    /// симметричным алгоритмом с преднастроенными раундовыми ключами.
    /// </summary>
    public interface ISymmetricCipher
    {
        /// <summary>
        /// Устанавливает ключ [де]шифрования и выполняет расширение ключа.
        /// </summary>
        /// <param name="key">Ключ [де]шифрования (массив байтов).</param>
        void SetKey(byte[] key);

        /// <summary>
        /// Шифрует один блок.
        /// </summary>
        /// <param name="block">Открытый блок (массив байтов).</param>
        /// <returns>Шифртекст (массив байтов).</returns>
        byte[] EncryptBlock(byte[] block);

        /// <summary>
        /// Дешифрует один блок.
        /// </summary>
        /// <param name="block">Шифртекст (массив байтов).</param>
        /// <returns>Открытый блок (массив байтов).</returns>
        byte[] DecryptBlock(byte[] block);
    }
}
