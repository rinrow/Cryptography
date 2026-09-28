using Crypto.DES;
using System;
using System.Collections.Generic;
using System.Text;

namespace Crypto.Tests;

[TestClass]
public class DesTests
{
    [TestMethod]
    public void DesRoundFunction_KnownVector()
    {
        var f = new DesRoundFunction();

        byte[] r0 = { 0xF0, 0xAA, 0xF0, 0xAA };
        byte[] k1 = { 0x1B, 0x02, 0xEF, 0xFC, 0x70, 0x72 };

        byte[] result = f.Transform(r0, k1);

        CollectionAssert.AreEqual(
            new byte[] { 0x23, 0x4A, 0xA9, 0xBB },
            result);
    }
}
