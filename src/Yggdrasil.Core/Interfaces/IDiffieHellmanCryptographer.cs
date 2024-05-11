using System.Security.Cryptography.X509Certificates;

namespace Yggdrasil.Core.Interfaces;
public interface IDiffieHellmanCryptographer
{
    Task<string?> EncryptAsync(string text, X509Certificate2 publicKeyCertificate, X509Certificate2 privateKeyCertificate,
        CancellationToken cancellationToken = default);

    Task<string?> DecryptAsync(string cipher, X509Certificate2 publicKeyCertificate, X509Certificate2 privateKeyCertificate);
}
