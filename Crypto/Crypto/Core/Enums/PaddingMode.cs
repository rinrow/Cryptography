using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Core.Enums
{
    /// <summary>
    /// Режим набивки (дополнения) последнего блока до полного размера.
    /// </summary>
    public enum PaddingMode
    {
        Zeros,
        AnsiX923,
        Pkcs7,
        Iso10126
    }
}
