using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Core.Interfaces
{
    /// <summary>
    /// Описание функционала процедуры расширения ключа
    /// (генерации раундовых ключей).
    /// </summary>
    public interface IKeyExpansion
    {
        /// <summary>
        /// Выполняет расширение входного ключа в массив раундовых ключей.
        /// </summary>
        /// <param name="key">
        /// Входной ключ шифрования (массив байтов).
        /// </param>
        /// <returns>
        /// Массив раундовых ключей. Каждый раундовый ключ — массив байтов.
        /// Порядок элементов соответствует порядку раундов алгоритма.
        /// </returns>
        byte[][] ExpandKey(byte[] key);
    }
}
