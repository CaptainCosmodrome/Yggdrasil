using Moq;
using Shouldly;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Cryptography;
using Yggdrasil.Security.Cryptography.Providers;

namespace Yggdrasil.Security.UnitTests.Cryptography;

[TestFixture]
public class CryptographerTests
{
    private ICryptographer _target;

    private Mock<ICryptographicAlgorithmProvider> _algoritmProviderMock;

    [SetUp]
    public void BeforeEachTest()
    {
        _algoritmProviderMock = new Mock<ICryptographicAlgorithmProvider>();

        _target = new Cryptographer(_algoritmProviderMock.Object);
    }

    [Test]
    public async Task EncryptAsync_UsingAesAndRfc2989_GivenKeySaltAndIterations_ProducesExpectedCipher()
    {
        var key = "tvbxsq589ku8elk924vpq99k2wrz86gz";
        var salt = "5tj7ssrt0aoluihuge30agq8vpdtxi81";
        var iterations = 1000;

        _algoritmProviderMock.Setup(_ => _.CreateSymmetricAlgorithm(It.Is<string>(x => string.Equals(x, key)),
                It.Is<string>(x => string.Equals(x, salt)),
                It.Is<int>(x => x == iterations)))
            .Returns(new AesAlgorithmProvider(new Rfc2989CryptographicKeyGenerator()).CreateSymmetricAlgorithm(key,
                salt, iterations));

        var text = "Thi$ is a tes7";

        var expected = "hWG5ZdsIBbgQsCC6FkZIfw==";

        var cipher = await _target.EncryptAsync(text, key, salt, iterations);

        cipher.ShouldBe(expected);
    }

    [Test]
    public async Task DecryptAsync_UsingAesAndRfc2989_GivenCipherKeySaltAndIterations_ProducesExpectedText()
    {
        var key = "tvbxsq589ku8elk924vpq99k2wrz86gz";
        var salt = "5tj7ssrt0aoluihuge30agq8vpdtxi81";
        var iterations = 1000;

        _algoritmProviderMock.Setup(_ => _.CreateSymmetricAlgorithm(It.Is<string>(x => string.Equals(x, key)),
                It.Is<string>(x => string.Equals(x, salt)),
                It.Is<int>(x => x == iterations)))
            .Returns(new AesAlgorithmProvider(new Rfc2989CryptographicKeyGenerator()).CreateSymmetricAlgorithm(key,
                salt, iterations));

        var expected = "Thi$ is a tes7";

        var cipher = "hWG5ZdsIBbgQsCC6FkZIfw==";

        var text = await _target.DecryptAsync(cipher, key, salt, iterations);

        text.ShouldBe(expected);
    }
}
