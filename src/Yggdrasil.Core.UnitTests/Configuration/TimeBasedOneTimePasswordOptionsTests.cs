using System;
using System.Linq;
using Yggdrasil.Core.Configuration;
using Yggdrasil.Core.Enums;

namespace Yggdrasil.Core.UnitTests.Configuration;

[TestFixture]
public class TimeBasedOneTimePasswordOptionsTests
{
    private TimeBasedOneTimePasswordOptions _target;

    private string _rawKey20 = "12345678901234567890";
    private string _rawKey32 = "12345678901234567890123456789012";
    private string _rawKey64 = "1234567890123456789012345678901234567890123456789012345678901234";

    private string _base16Key20 = "3132333435363738393031323334353637383930";
    private string _base16Key32 = "3132333435363738393031323334353637383930" +
                                  "313233343536373839303132";
    private string _base16Key64 = "3132333435363738393031323334353637383930" +
                                  "3132333435363738393031323334353637383930" +
                                  "3132333435363738393031323334353637383930" +
                                  "31323334";

    private string _base64Key20 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=";
    private string _base64Key32 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";
    private string _base64Key64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==";

    private byte[] _expectedKey20 = new byte[]
    {
        49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48
    };

    private byte[] _expectedKey32 = new byte[]
    {
        49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50
    };

    private byte[] _expectedKey64 = new byte[]
    {
        49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 
        51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 49, 50, 51, 52
    };

    [SetUp]
    public void BeforeEachTest()
    {
        _target = new TimeBasedOneTimePasswordOptions();
    }

    [Test]
    public void SetRawSecret_WhenSecretNotValidLength_ThrowsException()
    {
        Should.Throw<ArgumentOutOfRangeException>(() => _target.SetRawSecret("abc123"));
    }

    [Test]
    public void SetRawSecret_UsingSha1_ProducesExpectedKeyAndHashMode()
    {
        _target.SetRawSecret(_rawKey20);

        _target.Secret.ToArray().ShouldBe(_expectedKey20);
        _target.HashMode.ShouldBe(TotpHashMode.Sha1);
    }

    [Test]
    public void SetRawSecret_UsingSha256_ProducesExpectedKeyAndHashMode()
    {
        _target.SetRawSecret(_rawKey32);

        _target.Secret.ToArray().ShouldBe(_expectedKey32);
        _target.HashMode.ShouldBe(TotpHashMode.Sha256);
    }

    [Test]
    public void SetRawSecret_UsingSha512_ProducesExpectedKeyAndHashMode()
    {
        _target.SetRawSecret(_rawKey64);

        _target.Secret.ToArray().ShouldBe(_expectedKey64);
        _target.HashMode.ShouldBe(TotpHashMode.Sha512);
    }

    [Test]
    public void SetHexStringSecret_UsingSha1_ProducesExpectedKeyAndHashMode()
    {
        _target.SetHexStringSecret(_base16Key20);

        _target.Secret.ToArray().ShouldBe(_expectedKey20);
        _target.HashMode.ShouldBe(TotpHashMode.Sha1);
    }

    [Test]
    public void SetHexStringSecret_UsingSha256_ProducesExpectedKeyAndHashMode()
    {
        _target.SetHexStringSecret(_base16Key32);

        _target.Secret.ToArray().ShouldBe(_expectedKey32);
        _target.HashMode.ShouldBe(TotpHashMode.Sha256);
    }

    [Test]
    public void SetHexStringSecret_UsingSha512_ProducesExpectedKeyAndHashMode()
    {
        _target.SetHexStringSecret(_base16Key64);

        _target.Secret.ToArray().ShouldBe(_expectedKey64);
        _target.HashMode.ShouldBe(TotpHashMode.Sha512);
    }

    [Test]
    public void SetBase64Secret_UsingSha1_ProducesExpectedKeyAndHashMode()
    {
        _target.SetBase64Secret(_base64Key20);

        _target.Secret.ToArray().ShouldBe(_expectedKey20);
        _target.HashMode.ShouldBe(TotpHashMode.Sha1);
    }

    [Test]
    public void SetBase64Secret_UsingSha256_ProducesExpectedKeyAndHashMode()
    {
        _target.SetBase64Secret(_base64Key32);

        _target.Secret.ToArray().ShouldBe(_expectedKey32);
        _target.HashMode.ShouldBe(TotpHashMode.Sha256);
    }

    [Test]
    public void SetBase64Secret_UsingSha512_ProducesExpectedKeyAndHashMode()
    {
        _target.SetBase64Secret(_base64Key64);

        _target.Secret.ToArray().ShouldBe(_expectedKey64);
        _target.HashMode.ShouldBe(TotpHashMode.Sha512);
    }
}

