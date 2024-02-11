using System.Text;
using Yggdrasil.Core.Configuration;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Helpers;

namespace Yggdrasil.Security.OneTimePassword;

public class Rfc6238OneTimePasswordProvider
    (TimeBasedOneTimePasswordOptions options = null) : ITimeBasedOneTimePasswordProvider
{
    private readonly TimeBasedOneTimePasswordOptions _options = options ?? new TimeBasedOneTimePasswordOptions();

    public void VerifyOptions()
    {
        if (!(_options.Secret?.Any() ?? false))
        {
            throw new ArgumentException("In order to create a TOTP, you must first define the key", 
                nameof(TimeBasedOneTimePasswordOptions));
        }
    }

    /// <summary>
    /// Generate an OTP using the secret defined in the options
    /// </summary>
    /// <param name="codeDigits">the number of digits in the code</param>
    /// <returns></returns>
    public string GenerateOneTimePassword(int codeDigits = 6)
    {
        VerifyOptions();

        return Rfc6238Helper.Rfc6238(_options.Secret, timestamp: DateTime.UtcNow.Ticks, codeDigits: codeDigits);
    }

    /// <summary>
    /// Generate an OTP using a custom secret
    /// </summary>
    /// <param name="secret">the raw secret string to use to generate this totp</param>
    /// <param name="codeDigits">the number of digits in the code</param>
    /// <returns></returns>
    public string GenerateOneTimePassword(string secret, int codeDigits = 6)
    {
        return Rfc6238Helper.Rfc6238(Encoding.UTF8.GetBytes(secret), timestamp: DateTime.UtcNow.Ticks, codeDigits: codeDigits);
    }
}

