using Azure.Core;

namespace Yggdrasil.Configuration.Azure.Configuration;

public class AzureConfigurationServiceOptions
{
    public string AzureConfigurationServiceUrl { get; set; }
    public TokenCredential Credentials { get; set; }
}

