using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Core.Enums
{
    /// <summary>
    /// Режим шифрования блочного симметричного алгоритма.
    /// </summary>
    public enum CipherMode
    {
        ECB,
        CBC,
        PCBC,
        CFB,
        OFB,
        CTR,
        RandomDelta
    }
}
