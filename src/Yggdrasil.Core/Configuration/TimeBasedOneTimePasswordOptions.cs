using System.Text;
using Yggdrasil.Core.Enums;

namespace Yggdrasil.Core.Configuration;

public class TimeBasedOneTimePasswordOptions
{
    public byte[] Secret { get; private set; }

    public TotpHashMode HashMode { get; private set; }

    public TimeBasedOneTimePasswordOptions SetRawSecret(string secret)
    {
        SetSecret(secret);

        return this;
    }

    public TimeBasedOneTimePasswordOptions SetHexStringSecret(string hexSecret)
    {
        SetSecret(Encoding.UTF8.GetString(Convert.FromHexString(hexSecret)));

        return this;
    }

    public TimeBasedOneTimePasswordOptions SetBase64Secret(string base64Secret)
    {
        SetSecret(Encoding.UTF8.GetString(Convert.FromBase64String(base64Secret)));

        return this;
    }

    private void SetSecret(string rawSecret)
    {
        if (rawSecret.Length == 20)
        {
            HashMode = TotpHashMode.Sha1;
        }
        else if (rawSecret.Length == 32)
        {
            HashMode = TotpHashMode.Sha256;
        }
        else if (rawSecret.Length == 64)
        {
            HashMode = TotpHashMode.Sha512;
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(rawSecret),
                "A valid secret may only be 20 (SHA1), 32 (SHA256), or 64 (SHA512) characters in length");
        }

        Secret = Encoding.UTF8.GetBytes(rawSecret);
    }
}

