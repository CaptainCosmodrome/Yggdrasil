using Microsoft.Extensions.DependencyInjection;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security;
using Yggdrasil.Security.Cryptography;
using Yggdrasil.Security.Hmac;

namespace Yggdrasil.Core.DependencyInjection;

public static class DependencyInjection
{
    public static IServiceCollection RegisterCryptography(this IServiceCollection services, Action<SecurityConfigurationOptions> action = null)
    {
        var options = new SecurityConfigurationOptions();

        if (action != null)
        {
            action(options);
        }
        
        services.AddSingleton(typeof(ICryptographicKeyProvider), options.DefaultKeyProviderType);
        services.AddSingleton(typeof(ICryptographicAlgorithmProvider), options.DefaultAlgorithmProviderType);
        services.AddSingleton<ICryptographer, Cryptographer>();

        services.AddSingleton<IExpiringHmacProvider, ExpiringHmacProvider>();

        return services;
    }
}

