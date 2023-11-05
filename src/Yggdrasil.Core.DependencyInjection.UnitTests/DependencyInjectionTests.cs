using Microsoft.Extensions.DependencyInjection;

namespace Yggdrasil.Core.DependencyInjection.UnitTests;

[TestFixture]
public class DependencyInjectionTests
{
    [Test]
    public void RegisterCryptography_CreatesValidRegistration()
    {
        IServiceCollection services = new ServiceCollection();

        services.RegisterCryptography();

        Should.NotThrow(() => services.BuildServiceProvider(true)) ;
    }
}

