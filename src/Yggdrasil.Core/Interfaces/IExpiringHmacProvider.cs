using Yggdrasil.Core.Enums;

namespace Yggdrasil.Core.Interfaces;

public interface IExpiringHmacProvider
{
    Task<string> GenerateHmacAsync(string key, string salt, TimeSpan lifetime, int iterations = 1000,
        params string[] data);

    Task<string> GenerateHmacAsync(string key, string salt, DateTime expiry, int iterations = 1000, 
        params string[] data);

    Task<HmacValidationResult> ValidateHmacAsync(string hmac, string key, string salt, int iterations = 1000, params string[] data);
}

