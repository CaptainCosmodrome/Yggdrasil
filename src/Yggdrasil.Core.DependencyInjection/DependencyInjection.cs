using Microsoft.Extensions.DependencyInjection;
using Yggdrasil.Core.Configuration;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Cryptography;
using Yggdrasil.Security.Hmac;
using Yggdrasil.Security.OneTimePassword;

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

        services.AddTransient<HmacOneTimePasswordOptions>(ctx => options.HmacOneTimePasswordOptions);
        services.AddTransient<TimeBasedOneTimePasswordOptions>(ctx => options.TimeBasedOneTimePasswordOptions);
        
        services.AddSingleton(typeof(ICryptographicKeyProvider), options.DefaultKeyProviderType);
        services.AddSingleton(typeof(ICryptographicAlgorithmProvider), options.DefaultAlgorithmProviderType);
        services.AddSingleton<ICryptographer, Cryptographer>();

        services.AddTransient<IExpiringHmacProvider, ExpiringHmacProvider>();
        services.AddTransient<IHmacBasedOneTimePasswordProvider, Rfc4226OneTimePasswordProvider>();

        return services;
    }
}

