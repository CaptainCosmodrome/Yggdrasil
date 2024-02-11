using System.Security.Cryptography.X509Certificates;
using Yggdrasil.Security.Certificates.Algorithms;

namespace Yggdrasil.Security.Certificates.Interfaces;

public interface ICertificateFactory
{
    X509Certificate2 GenerateCertificate(AlgorithmDefinition algorithm, string name, TimeSpan lifetime, string? friendlyName = null, X509Certificate2? issuer = null);
}