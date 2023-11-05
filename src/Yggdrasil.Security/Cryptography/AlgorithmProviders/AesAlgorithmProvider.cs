using System.Security.Cryptography;
using Yggdrasil.Core.Interfaces;

namespace Yggdrasil.Security.Cryptography.AlgorithmProviders;

public class AesAlgorithmProvider : ICryptographicAlgorithmProvider
{
    private readonly ICryptographicKeyProvider _keyGenerator;

    public AesAlgorithmProvider(ICryptographicKeyProvider keyGenerator)
    {
        _keyGenerator = keyGenerator;
    }

    public SymmetricAlgorithm CreateSymmetricAlgorithm(string key, string salt, int iterations = 1000)
    {
        var provider = Aes.Create();

        provider.Padding = PaddingMode.PKCS7;

        var derivedKey = _keyGenerator.CreateKey(key, salt, iterations);

        provider.KeySize = provider.LegalKeySizes[0].MaxSize;
        provider.BlockSize = provider.LegalBlockSizes[0].MaxSize;

        provider.Key = derivedKey.GetBytes(provider.KeySize / 8);
        provider.IV = derivedKey.GetBytes(provider.BlockSize / 8);

        return provider;
    }
}
