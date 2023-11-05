using Yggdrasil.Security.Helpers;

namespace Yggdrasil.Security.UnitTests.Helpers;

[TestFixture]
public class Rfc4226HelperTests
{
    /// <summary>
    /// This test pulled from the whitepaper.  It should not be changed unless the whitepaper changes with a new test
    /// </summary>
    /// <see cref="https://datatracker.ietf.org/doc/html/rfc4226"/>
    [Test]
    public void Rfc4226_ProvidedWhitePaperTestCase_CreatesExpectedResult()
    {
        var codeDigits = 6;
        var hmac = new byte[]
        {
            0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b,
            0x55, 0x5a
        };
        //var offset = hmac[19] & 0xf;

        var expected = "872921";

        var result = Rfc4226Helper.Rfc4226(hmac, codeDigits);

        result.ShouldBe(expected);
    }
}

