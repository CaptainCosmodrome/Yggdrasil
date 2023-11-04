using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Cryptography.KeyGenerators;

namespace Yggdrasil.Security;

public class SecurityConfigurationOptions
{
    public Type DefaultKeyGeneratorType { get; set; } = typeof(Rfc2989CryptographicKeyGenerator);
    public Type DefaultAlgorithmProviderType { get; set; } = typeof(Rfc2989CryptographicKeyGenerator);

    public SecurityConfigurationOptions SetDefaultKeyGenerator<TKeyGenerator>() where TKeyGenerator : ICryptographicKeyGenerator
    {
        DefaultKeyGeneratorType = typeof(TKeyGenerator);

        return this;
    }

    public SecurityConfigurationOptions SetDefaultAlgorithmProvider<TAlgorithmProvider>() where TAlgorithmProvider : ICryptographicAlgorithmProvider
    {
        DefaultAlgorithmProviderType = typeof(TAlgorithmProvider);

        return this;
    }
}

