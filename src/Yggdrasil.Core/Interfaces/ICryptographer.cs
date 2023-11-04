namespace Yggdrasil.Core.Interfaces;

public interface ICryptographer
{
    Task<string> DecryptAsync(string cipher, string key, string salt, int iterations = 1000);
    Task<string> EncryptAsync(string text, string key, string salt, int iterations = 1000, CancellationToken cancellationToken = default);
}
