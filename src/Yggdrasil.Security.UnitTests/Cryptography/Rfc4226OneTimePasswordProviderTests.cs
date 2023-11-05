using Yggdrasil.Core.Enums;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.OneTimePassword;

namespace Yggdrasil.Security.UnitTests.Cryptography;

[TestFixture]
public class Rfc4226OneTimePasswordProviderTests
{
    private IHmacBasedOneTimePasswordProvider _target;

    [SetUp]
    public void BeforeEachTest()
    {
        _target = new Rfc4226OneTimePasswordProvider();
    }

    [Test]
    public void CreateOneTimePassword_UsingSameSecretAndMovingFactor_CreatesSameOtp()
    {
        var secret = Guid.NewGuid().ToString();
        var movingFactor = 123;

        var otp1 = _target.CreateOneTimePassword(secret, movingFactor);

        _target.ValidateOneTimePassword(otp1, secret, movingFactor).ShouldBe(OneTimePasswordValidationResult.Valid);

        var otp2 = _target.CreateOneTimePassword(secret, movingFactor);

        _target.ValidateOneTimePassword(otp2, secret, movingFactor).ShouldBe(OneTimePasswordValidationResult.Valid);

        otp2.ShouldBe(otp1);
    }

    [Test]
    public void CreateOneTimePassword_UsingSameSecret_ButDifferentMovingFactor_CreatesDifferentOtp()
    {
        var secret = Guid.NewGuid().ToString();
        var movingFactor = 123;

        var otp1 = _target.CreateOneTimePassword(secret, movingFactor++);

        _target.ValidateOneTimePassword(otp1, secret, movingFactor-1).ShouldBe(OneTimePasswordValidationResult.Valid);

        var otp2 = _target.CreateOneTimePassword(secret, movingFactor);

        _target.ValidateOneTimePassword(otp2, secret, movingFactor).ShouldBe(OneTimePasswordValidationResult.Valid);

        otp2.ShouldNotBe(otp1);
    }

    [Test]
    public void CreateOneTimePassword_UsingSameSecretAndMovingFactor_OtpIsValid()
    {
        var secret = Guid.NewGuid().ToString();
        var movingFactor = 123;

        var otp = _target.CreateOneTimePassword(secret, movingFactor);

        var result = _target.ValidateOneTimePassword(otp, secret, movingFactor);

        result.ShouldBe(OneTimePasswordValidationResult.Valid);
    }

    [Test]
    public void ValidateOneTimePassword_WhenIncorrectDigitProvided_ReturnsNoMatch()
    {
        var secret = "8524749d-c955-40b9-b25d-6d01194c9576";
        var movingFactor = 123;

        var otp = "282131"; // expected = 182131

        var result = _target.ValidateOneTimePassword(otp, secret, movingFactor, addChecksum: false);

        result.ShouldBe(OneTimePasswordValidationResult.NoMatch);
    }

    [Test]
    public void ValidateOneTimePassword_WhenOtpIsNonNumeric_REturnsInvalid()
    {
        var secret = Guid.NewGuid().ToString();
        var movingFactor = 123;

        var result = _target.ValidateOneTimePassword("123A56", secret, movingFactor, addChecksum: false);

        result.ShouldBe(OneTimePasswordValidationResult.Invalid);
    }

    [Test]
    public void ValidateOneTimePassword_WhenOtpIsIncorrectLength_ReturnsInvalid()
    {
        var secret = Guid.NewGuid().ToString();
        var movingFactor = 123;

        var result = _target.ValidateOneTimePassword("12356", secret, movingFactor);

        result.ShouldBe(OneTimePasswordValidationResult.InvalidLength);
    }

    [Test]
    public void ValidateOneTimePassword_WhenChecksumIsInvalid_ReturnsInvalidChecksum()
    {
        var secret = "8524749d-c955-40b9-b25d-6d01194c9576";
        var movingFactor = 123;

        var otp = "1821312"; // expected = 1821313

        var result = _target.ValidateOneTimePassword(otp, secret, movingFactor, 6, true);

        result.ShouldBe(OneTimePasswordValidationResult.InvalidChecksum);
    }
}

