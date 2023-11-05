

using System.CodeDom;
using Yggdrasil.Core.Enums;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Cryptography;
using Yggdrasil.Security.Cryptography.AlgorithmProviders;
using Yggdrasil.Security.Cryptography.KeyGenerators;
using Yggdrasil.Security.Hmac;

namespace Yggdrasil.Security.UnitTests.Hmac;

[TestFixture]
public class ExpiringHmacProviderTests
{
    private IExpiringHmacProvider _target;

    private ICryptographer _crypto;

    [SetUp]
    public void BeforeEachTest()
    {
        _crypto = new Cryptographer(new AesAlgorithmProvider(new Rfc2989CryptographicKeyProvider()));

        _target = new ExpiringHmacProvider(_crypto);
    }

    [Test]
    public async Task GenerateHmacAsync_ValidateHmacAsync_WhenDataAndKeysMatch_AndNotExpired_ReturnsValidResult()
    {
        var key = "tvbxsq589ku8elk924vpq99k2wrz86gz";
        var salt = "5tj7ssrt0aoluihuge30agq8vpdtxi81";
        var iterations = 1000;

        var data = Guid.NewGuid().ToString();

        var hmac = await _target.GenerateHmacAsync(key, salt, TimeSpan.FromHours(24), iterations, data);

        var result = await _target.ValidateHmacAsync(hmac, key, salt, iterations, data);

        result.ShouldBe(HmacValidationResult.Valid);
    }

    [Test]
    public async Task GenerateHmacAsync_ValidateHmacAsync_WhenDataAndKeysMatch_AndExpired_ReturnsExpiredResult()
    {
        var key = "tvbxsq589ku8elk924vpq99k2wrz86gz";
        var salt = "5tj7ssrt0aoluihuge30agq8vpdtxi81";
        var iterations = 1000;

        var data = Guid.NewGuid().ToString();

        var hmac = await _target.GenerateHmacAsync(key, salt, TimeSpan.FromMilliseconds(1), iterations, data);

        await Task.Delay(100);

        var result = await _target.ValidateHmacAsync(hmac, key, salt, iterations, data);

        result.ShouldBe(HmacValidationResult.Expired);
    }

    [Test]
    public async Task GenerateHmacAsync_ValidateHmacAsync_WhenKeyChanges_AndNotExpired_ReturnsInvalidResult()
    {
        var key = "tvbxsq589ku8elk924vpq99k2wrz86gz";
        var salt = "5tj7ssrt0aoluihuge30agq8vpdtxi81";
        var iterations = 1000;

        var data = Guid.NewGuid().ToString();

        var hmac = await _target.GenerateHmacAsync(key, salt, TimeSpan.FromHours(24), iterations, data);

        var result = await _target.ValidateHmacAsync(hmac, "tvbxsq589ku8elk924vpq99k2wrz86gd", salt, iterations, data);

        result.ShouldBe(HmacValidationResult.Invalid);
    }

    [Test]
    public async Task ValidateHmacAsync_WhenHmacNotBase64String_ReturnsInvalid()
    {
        var key = "tvbxsq589ku8elk924vpq99k2wrz86gz";
        var salt = "5tj7ssrt0aoluihuge30agq8vpdtxi81";
        var iterations = 1000;

        var data = Guid.NewGuid().ToString();
        var hmac = "ABCDEFGH";

        var result = await _target.ValidateHmacAsync(hmac, key, salt, iterations, data);

        result.ShouldBe(HmacValidationResult.Invalid);
    }
}

