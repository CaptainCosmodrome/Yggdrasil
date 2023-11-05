using Yggdrasil.Core.Enums;
using Yggdrasil.Security.Helpers;

namespace Yggdrasil.Security.UnitTests.Helpers;

/// <summary>
/// Tests of the totp generator using the white paper test case
/// </summary>
/// <remarks>
/// The secrets for this test are strings of 20 (SHA1), 32 (SHA256), and 64 (SHA512) characters encoded as either hex or base 64 strings, then loaded into byte arrays.
/// </remarks>
[TestFixture]
public class Rfc6238HelperTests
{
    [TestCase(59, "94287082")]
    [TestCase(1111111109, "07081804")]
    [TestCase(1111111111, "14050471")]
    [TestCase(1234567890, "89005924")]
    [TestCase(2000000000, "69279037")]
    [TestCase(20000000000, "65353130")]
    public void Rfc6238_UsingSha1_CreatesExpectedResult(long timeInSeconds, string expected)
    {
        // Seed for HMAC-SHA1 - 20 bytes
        var secret = "3132333435363738393031323334353637383930";

        //the time in seconds is the seconds from unix epoch
        var timestamp = TimeSpan.FromSeconds((double)timeInSeconds).Ticks + DateTime.UnixEpoch.Ticks;

        var result = Rfc6238Helper.Rfc6238(Convert.FromHexString(secret), timestamp, 30, 8, TotpHashMode.Sha1);

        result.ShouldBe(expected);
    }

    [TestCase(59, "46119246")]
    [TestCase(1111111109, "68084774")]
    [TestCase(1111111111, "67062674")]
    [TestCase(1234567890, "91819424")]
    [TestCase(2000000000, "90698825")]
    [TestCase(20000000000, "77737706")]
    public void Rfc6238_UsingSha256_CreatesExpectedResult(long timeInSeconds, string expected)
    {
        // Seed for HMAC-SHA256 - 32 bytes
        var secret = "3132333435363738393031323334353637383930" +
                     "313233343536373839303132";

        //the time in seconds is the seconds from unix epoch
        var timestamp = TimeSpan.FromSeconds((double)timeInSeconds).Ticks + DateTime.UnixEpoch.Ticks;

        var result = Rfc6238Helper.Rfc6238(Convert.FromHexString(secret), timestamp, 30, 8, TotpHashMode.Sha256);

        result.ShouldBe(expected);
    }

    [TestCase(59, "90693936")]
    [TestCase(1111111109, "25091201")]
    [TestCase(1111111111, "99943326")]
    [TestCase(1234567890, "93441116")]
    [TestCase(2000000000, "38618901")]
    [TestCase(20000000000, "47863826")]
    public void Rfc6238_UsingSha512_CreatesExpectedResult(long timeInSeconds, string expected)
    {
        // Seed for HMAC-SHA512 - 64 bytes
        var secret = "3132333435363738393031323334353637383930" +
                        "3132333435363738393031323334353637383930" +
                        "3132333435363738393031323334353637383930" +
                        "31323334";

        //the time in seconds is the seconds from unix epoch
        var timestamp = TimeSpan.FromSeconds((double)timeInSeconds).Ticks + DateTime.UnixEpoch.Ticks;

        var result = Rfc6238Helper.Rfc6238(Convert.FromHexString(secret), timestamp, 30, 8, TotpHashMode.Sha512);

        result.ShouldBe(expected);
    }

    [TestCase(59, "0000000000000001")]
    [TestCase(1111111109, "00000000023523EC")]
    [TestCase(1111111111, "00000000023523ED")]
    [TestCase(1234567890, "000000000273EF07")]
    [TestCase(2000000000, "0000000003F940AA")]
    [TestCase(20000000000, "0000000027BC86AA")]
    public void CalculateStep_UsingWhitePaperTestCase_ProducesExpectedValues(long timeInSeconds, string tHex)
    {
        //the time in seconds is the seconds from unix epoch
        var timestamp = TimeSpan.FromSeconds((double)timeInSeconds).Ticks + DateTime.UnixEpoch.Ticks;

        var expected = Convert.ToInt64(tHex, 16);

        var result = Rfc6238Helper.CalculateStep(timestamp);

        result.ShouldBe(expected);
    }

    [TestCase(59, "94287082")]
    [TestCase(1111111109, "07081804")]
    [TestCase(1111111111, "14050471")]
    [TestCase(1234567890, "89005924")]
    [TestCase(2000000000, "69279037")]
    [TestCase(20000000000, "65353130")]
    public void Rfc6238_UsingSha1_WithBase64Key_ProducesExpectedResult(long timeInSeconds, string expected)
    {
        //20 characters encoded as base64
        var secret = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA=";

        //the time in seconds is the seconds from unix epoch
        var timestamp = TimeSpan.FromSeconds((double)timeInSeconds).Ticks + DateTime.UnixEpoch.Ticks;

        var result = Rfc6238Helper.Rfc6238(Convert.FromBase64String(secret), timestamp, 30, 8, TotpHashMode.Sha1);

        result.ShouldBe(expected);
    }

    [TestCase(59, "46119246")]
    [TestCase(1111111109, "68084774")]
    [TestCase(1111111111, "67062674")]
    [TestCase(1234567890, "91819424")]
    [TestCase(2000000000, "90698825")]
    [TestCase(20000000000, "77737706")]
    public void Rfc6238_UsingSha256_WithBase64Key_CreatesExpectedResult(long timeInSeconds, string expected)
    {
        //32 characters encoded as base64
        var secret = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=";

        //the time in seconds is the seconds from unix epoch
        var timestamp = TimeSpan.FromSeconds((double)timeInSeconds).Ticks + DateTime.UnixEpoch.Ticks;

        var result = Rfc6238Helper.Rfc6238(Convert.FromBase64String(secret), timestamp, 30, 8, TotpHashMode.Sha256);

        result.ShouldBe(expected);
    }

    [TestCase(59, "90693936")]
    [TestCase(1111111109, "25091201")]
    [TestCase(1111111111, "99943326")]
    [TestCase(1234567890, "93441116")]
    [TestCase(2000000000, "38618901")]
    [TestCase(20000000000, "47863826")]
    public void Rfc6238_UsingSha512_WithBase64Key_CreatesExpectedResult(long timeInSeconds, string expected)
    {
        //64 characters encoded as base64
        var secret = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNA==";

        //the time in seconds is the seconds from unix epoch
        var timestamp = TimeSpan.FromSeconds((double)timeInSeconds).Ticks + DateTime.UnixEpoch.Ticks;

        var result = Rfc6238Helper.Rfc6238(Convert.FromBase64String(secret), timestamp, 30, 8, TotpHashMode.Sha512);

        result.ShouldBe(expected);
    }
}

