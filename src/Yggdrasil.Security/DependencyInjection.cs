using Microsoft.Extensions.DependencyInjection;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Cryptography;

namespace Yggdrasil.Security
{
    public static class DependencyInjection
    {
        public static IServiceCollection RegisterCryptography(this IServiceCollection services, Action<SecurityConfigurationOptions> action)
        {
            var options = new SecurityConfigurationOptions();

            action(options);

            services.AddSingleton(typeof(ICryptographicKeyGenerator), options.DefaultKeyGeneratorType);
            services.AddSingleton(typeof(ICryptographicAlgorithmProvider), options.DefaultAlgorithmProviderType);
            services.AddSingleton<ICryptographer, Cryptographer>();

            return services;
        }
    }
}
