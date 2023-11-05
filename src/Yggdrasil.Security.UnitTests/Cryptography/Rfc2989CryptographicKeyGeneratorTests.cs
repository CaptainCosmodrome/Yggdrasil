using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Cryptography.KeyGenerators;

namespace Yggdrasil.Security.UnitTests.Cryptography;

[TestFixture]
public class Rfc2989CryptographicKeyGeneratorTests
{
    private ICryptographicKeyProvider _target;

    [SetUp]
    public void BeforeEachTest()
    {
        _target = new Rfc2989CryptographicKeyProvider();
    }

    [Test]
    public void CreateKey_GivenKeySaltAndIterations_GeneratesExpectedValue()
    {
        var key = "tvbxsq589ku8elk924vpq99k2wrz86gz";
        var salt = "5tj7ssrt0aoluihuge30agq8vpdtxi81";
        var iterations = 1000;

        var expected = "20Ub2K9mg8eshm6sS2t/jhOzvV4znIn5uQU57Lx9re8=";

        var derivedKey = _target.CreateKey(key, salt, iterations);

        var result = Convert.ToBase64String(derivedKey.GetBytes(32)); //  256 / 8 = 32

        result.ShouldBe(expected);
    }
}

