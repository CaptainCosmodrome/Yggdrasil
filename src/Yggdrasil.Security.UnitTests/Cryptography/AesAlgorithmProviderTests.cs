using Moq;
using Shouldly;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Cryptography.KeyGenerators;
using Yggdrasil.Security.Cryptography.Providers;

namespace Yggdrasil.Security.UnitTests.Cryptography;

[TestFixture]
public class AesAlgorithmProviderTests
{
    private ICryptographicAlgorithmProvider _target;

    private Mock<ICryptographicKeyGenerator> _keyGeneratorMock;

    [SetUp]
    public void BeforeEachTest()
    {
        _keyGeneratorMock = new Mock<ICryptographicKeyGenerator>();

        _target = new AesAlgorithmProvider(_keyGeneratorMock.Object);
    }

    [Test]
    public void CreateSymmetricAlgorithm_WithRfc2989Key_ProducesExpectedAesKey()
    {
        var key = "tvbxsq589ku8elk924vpq99k2wrz86gz";
        var salt = "5tj7ssrt0aoluihuge30agq8vpdtxi81";
        var iterations = 1000;

        var expected = "20Ub2K9mg8eshm6sS2t/jhOzvV4znIn5uQU57Lx9re8=";

        _keyGeneratorMock.Setup(_ => _.CreateKey(It.Is<string>(x => string.Equals(x, key)),
                It.Is<string>(x => string.Equals(x, salt)),
                It.Is<int>(x => x == iterations)))
            .Returns(new Rfc2989CryptographicKeyGenerator().CreateKey(key,
                salt, iterations));

        var algo = _target.CreateSymmetricAlgorithm(key, salt, iterations);

        Convert.ToBase64String(algo.Key).ShouldBe(expected);
    }

    [Test]
    public void CreateSymmetricAlgorithm_WithRfc2989Key_ProducesExpectedAesInitializationVector()
    {
        var key = "tvbxsq589ku8elk924vpq99k2wrz86gz";
        var salt = "5tj7ssrt0aoluihuge30agq8vpdtxi81";
        var iterations = 1000;

        var expected = "hAMbW1FGz/dH1IAvxfPi6w==";

        _keyGeneratorMock.Setup(_ => _.CreateKey(It.Is<string>(x => string.Equals(x, key)),
                It.Is<string>(x => string.Equals(x, salt)),
                It.Is<int>(x => x == iterations)))
            .Returns(new Rfc2989CryptographicKeyGenerator().CreateKey(key,
                salt, iterations));

        var algo = _target.CreateSymmetricAlgorithm(key, salt, iterations);

        Convert.ToBase64String(algo.IV).ShouldBe(expected);
    }
}

