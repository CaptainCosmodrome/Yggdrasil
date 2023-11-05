using System.Security.Cryptography;
using System.Text;
using Yggdrasil.Core.Enums;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Extensions;

namespace Yggdrasil.Security.Hmac;

public class ExpiringHmacProvider : IExpiringHmacProvider
{
    private readonly ICryptographer _cryptographer;

    public ExpiringHmacProvider(ICryptographer cryptographer)
    {
        _cryptographer = cryptographer;
    }

    public Task<string> GenerateHmacAsync(string key, string salt, TimeSpan lifetime, int iterations = 1000,
        params string[] data)
    {
        return GenerateHmacAsync(key, salt, DateTime.UtcNow.Add(lifetime), iterations, data);
    }

    public async Task<string> GenerateHmacAsync(string key, string salt, DateTime expiry, int iterations = 1000, 
        params string[] data)
    {
        string hmac = null;

        var keyBytes = Encoding.UTF8.GetBytes(key);

        using var sha512 = new HMACSHA512(keyBytes);

        //use the ticks in the payload so its hashed value changes even when data is the same
        var payload = $"{expiry.Ticks}{string.Join('|', data)}";

        using var ms = new MemoryStream(Encoding.UTF8.GetBytes(payload));
        var hashBytes = await sha512.ComputeHashAsync(ms);
        var hmacBytes = new byte[8 + hashBytes.Length];

        //skip the first 8 bytes and write the payload bytes
        hashBytes.CopyTo(hmacBytes, 8);

        //write the expiry timestamp as the first 8 bytes (we need this in order to be able to verify the hmac)
        BitConverter.GetBytes(expiry.Ticks).CopyTo(hmacBytes, 0);

        hmac = await _cryptographer.EncryptAsync(Convert.ToBase64String(hmacBytes), key, salt, iterations);

        return hmac.EncodeForQuerystring();
    }

    public async Task<HmacValidationResult> ValidateHmacAsync(string hmac, string key, string salt, int iterations = 1000, params string[] data)
    {
        var decodedHmac = hmac.DecodeFromQuerystring();

        var hmacBytes = new byte[0];

        try
        {
            hmacBytes = Convert.FromBase64String(await _cryptographer.DecryptAsync(decodedHmac, key, salt, iterations));
        }
        catch (FormatException e)
        {
            //when the hmac is not a valid base 64 string
            return HmacValidationResult.Invalid;
        }
        catch (CryptographicException e)
        {
            //when the hmac is not a valid encrypted string, return invalid
            return HmacValidationResult.Invalid;
        }

        var claimedExpiry = new DateTime(BitConverter.ToInt64(hmacBytes, 0));

        if (claimedExpiry < DateTime.UtcNow)
        {
            return HmacValidationResult.Expired;
        }

        var recreatedHmac = await GenerateHmacAsync(key, salt, claimedExpiry, iterations, data);

        if (string.Compare(decodedHmac, recreatedHmac.DecodeFromQuerystring(), StringComparison.Ordinal) == 0)
        {
            return HmacValidationResult.Valid;
        }

        return HmacValidationResult.Invalid;
    }
}

