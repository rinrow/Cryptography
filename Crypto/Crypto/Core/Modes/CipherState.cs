using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Core.Modes
{
    public sealed class CipherState
    {
        /// <summary>Предыдущий шифртекст (C_{i-1}). Для первого блока — IV.</summary>
        public byte[]? PreviousCipher { get; set; }

        /// <summary>Предыдущий открытый текст (P_{i-1}). Нужен для PCBC.</summary>
        public byte[]? PreviousPlain { get; set; }

        /// <summary>Счётчик блоков. Нужен для CTR (и Random Delta).</summary>
        public long Counter { get; set; }
    }
}
