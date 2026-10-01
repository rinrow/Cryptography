using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Core.Padding
{

    /// <summary>
    /// Описание функционала набивки (padding) для блочного шифра.
    /// </summary>
    public interface IPadding
    {
        /// <summary>
        /// Размер блока, под который работает набивка.
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Дополняет данные до кратного размера блока.
        /// Если длина уже кратна, добавляется целый блок набивки.
        /// </summary>
        /// <param name="data">Исходные данные.</param>
        /// <returns>Данные, длина которых кратна <see cref="BlockSize"/>.</returns>
        byte[] Pad(byte[] data);

        /// <summary>
        /// Удаляет набивку.
        /// </summary>
        /// <param name="data">Данные, длина которых кратна <see cref="BlockSize"/>.</param>
        /// <returns>Исходные данные без набивки.</returns>
        byte[] Unpad(byte[] data);
    }
}
