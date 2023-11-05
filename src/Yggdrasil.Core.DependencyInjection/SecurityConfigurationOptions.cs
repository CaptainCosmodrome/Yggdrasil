using Yggdrasil.Core.Configuration;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Cryptography.KeyGenerators;

namespace Yggdrasil.Core.DependencyInjection;

public class SecurityConfigurationOptions
{
    public Type DefaultKeyProviderType { get; private set; } = typeof(Rfc2989CryptographicKeyProvider);
    public Type DefaultAlgorithmProviderType { get; private set; } = typeof(Rfc2989CryptographicKeyProvider);

    public HmacOneTimePasswordOptions HmacOneTimePasswordOptions { get; private set; } = new HmacOneTimePasswordOptions();
    public TimeBasedOneTimePasswordOptions TimeBasedOneTimePasswordOptions { get; private set; } = new TimeBasedOneTimePasswordOptions();

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

    public SecurityConfigurationOptions ConfigureHmacOneTimePassword(Action<HmacOneTimePasswordOptions> action)
    {
        action(HmacOneTimePasswordOptions);

        return this;
    }

    public SecurityConfigurationOptions ConfigureTimeBasedOneTimePassword(Action<TimeBasedOneTimePasswordOptions> action)
    {
        action(TimeBasedOneTimePasswordOptions);

        return this;
    }
}

