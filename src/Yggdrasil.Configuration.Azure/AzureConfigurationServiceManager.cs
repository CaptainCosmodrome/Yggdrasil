using Microsoft.Extensions.Configuration;
using Microsoft.FeatureManagement;
using Yggdrasil.Core.Extensions;
using Yggdrasil.Core.Interfaces;

namespace Yggdrasil.Configuration.Azure;

public class AzureConfigurationServiceManager : IConfigurationManager
{
    private readonly IConfiguration _configuration;
    private readonly IFeatureManager _featureManager;

    public AzureConfigurationServiceManager(IConfiguration configuration, IFeatureManager featureManager)
    {
        _configuration = configuration;
        _featureManager = featureManager;
    }

    public Task<bool> IsFeatureFlagEnabledAsync(string key)
    {
        return _featureManager.IsEnabledAsync(key);
    }

    public async Task<bool> IsFeatureFlagDisabledAsync(string key)
    {
        var enabled = await IsFeatureFlagEnabledAsync(key);

        return !enabled;
    }

    public TValue GetConfigurationValue<TValue>(string key)
    {
        return _configuration[key].SafeChangeType<TValue>();
    }
}

