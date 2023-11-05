using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Cryptography.KeyGenerators;

namespace Yggdrasil.Security;

public class SecurityConfigurationOptions
{
    public Type DefaultKeyProviderType { get; set; } = typeof(Rfc2989CryptographicKeyProvider);
    public Type DefaultAlgorithmProviderType { get; set; } = typeof(Rfc2989CryptographicKeyProvider);

    public SecurityConfigurationOptions SetDefaultKeyGenerator<TKeyProvider>() where TKeyProvider : ICryptographicKeyProvider
    {
        DefaultKeyProviderType = typeof(TKeyProvider);

        return this;
    }

    public SecurityConfigurationOptions SetDefaultAlgorithmProvider<TAlgorithmProvider>() where TAlgorithmProvider : ICryptographicAlgorithmProvider
    {
        DefaultAlgorithmProviderType = typeof(TAlgorithmProvider);

        return this;
    }
}

