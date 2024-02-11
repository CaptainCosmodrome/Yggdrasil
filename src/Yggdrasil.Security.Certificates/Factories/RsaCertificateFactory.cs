using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Yggdrasil.Security.Certificates.Algorithms;
using Yggdrasil.Security.Certificates.Interfaces;
using Yggdrasil.Security.Certificates.Extensions;
using Yggdrasil.Security.Certificates.Helpers;

namespace Yggdrasil.Security.Certificates.Factories;
public class RsaCertificateFactory : ICertificateFactory
{
    public X509Certificate2 GenerateCertificate(AlgorithmDefinition algorithm, string name, TimeSpan lifetime,
        string? friendlyName = null, X509Certificate2? issuer = null)
    {
        if (!algorithm.IsRsaAlgorithm())
        {
            throw new ArgumentException($"Invalid Algorithm for an ECDsa Certificate: [{algorithm.KeyStrength}][{algorithm.SigningAlgorithm}]", nameof(algorithm));
        }

        using var key = RSA.Create(algorithm.KeyStrength);

        if (issuer == null)
        {
            var issuerCertificateRequest = new CertificateRequest($"CN={name}", key, algorithm.HashAlgorithm, RSASignaturePadding.Pkcs1);

            issuerCertificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

            issuerCertificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(issuerCertificateRequest.PublicKey, false));

            return issuerCertificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-45),
                DateTimeOffset.UtcNow.Add(lifetime));
        }

        var certificateRequest = new CertificateRequest($"CN={name}",  key, algorithm.HashAlgorithm, RSASignaturePadding.Pkcs1);

        certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,
            false, 0, false));

        certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
            false));

        certificateRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
        {
            new Oid("1.3.6.1.5.5.7.3.8")
        }, true));

        certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

        return certificateRequest.Create(
        issuer,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(90),
            CertificateHelper.GenerateSerialNumber(name));
    }
}
