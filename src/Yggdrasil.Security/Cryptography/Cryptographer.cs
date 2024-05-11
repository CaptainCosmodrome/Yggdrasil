using System.Security.Cryptography;
using Yggdrasil.Core.Interfaces;

namespace Yggdrasil.Security.Cryptography;

public class Cryptographer(ICryptographicAlgorithmProvider algorithmProvider) : ICryptographer
{
    public async Task<string> EncryptAsync(string text, string key, string salt, int iterations = 1000, 
        CancellationToken cancellationToken = default)
    {
        string cipher = null;

        using var algorithm = algorithmProvider.CreateSymmetricAlgorithm(key, salt, iterations);
        using var ms = new MemoryStream();
        await using var crypto = new CryptoStream(ms, algorithm.CreateEncryptor(), CryptoStreamMode.Write);
        await using var sw = new StreamWriter(crypto);

        await sw.WriteAsync(text);
        await sw.FlushAsync();
        await crypto.FlushFinalBlockAsync(cancellationToken);
        await ms.FlushAsync(cancellationToken);

        cipher = Convert.ToBase64String(ms.GetBuffer(), 0, Convert.ToInt32(ms.Length));

        return cipher;
    }

    public async Task<string> DecryptAsync(string cipher, string key, string salt, int iterations = 1000)
    {
        var rawData = Convert.FromBase64String(cipher);

        string result = null;

        using var algorithm = algorithmProvider.CreateSymmetricAlgorithm(key, salt, iterations);
        using var ms = new MemoryStream(rawData);
        await using var crypto = new CryptoStream(ms, algorithm.CreateDecryptor(), CryptoStreamMode.Read);
        using var sr = new StreamReader(crypto);

        result = await sr.ReadToEndAsync();

        return result;
    }
}
