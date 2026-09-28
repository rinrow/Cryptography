using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Core.Interfaces
{
    /// <summary>
    /// Описание функционала по выполнению шифрующего преобразования
    /// (раундовой функции) над блоком данных.
    /// </summary>
    public interface IRoundFunction
    {
        /// <summary>
        /// Применяет шифрующее преобразование к входному блоку
        /// с использованием заданного раундового ключа.
        /// </summary>
        /// <param name="block">Входной блок (массив байтов).</param>
        /// <param name="roundKey">Раундовый ключ (массив байтов).</param>
        /// <returns>Выходной блок (массив байтов).</returns>
        byte[] Transform(byte[] block, byte[] roundKey);
    }
}
