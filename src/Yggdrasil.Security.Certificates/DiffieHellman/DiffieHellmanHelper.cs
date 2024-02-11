using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace Yggdrasil.Security.Certificates.DiffieHellman;
public static  class DiffieHellmanHelper
{
    private static byte[] GetDerivedKey(X509Certificate2 publicCertificate, X509Certificate2 privateCertificate)
    {
        byte[] derivedKey;

        using (var privateKey = (ECDsaCng)privateCertificate.GetECDsaPrivateKey())
        using (var publicKey = (ECDsaCng)publicCertificate.GetECDsaPublicKey())
        {
            var publicParams = publicKey.ExportParameters(false);

            using (var publicCng = ECDiffieHellmanCng.Create(publicParams))
            using (var diffieHellman = new ECDiffieHellmanCng(privateKey.Key))
            {
                derivedKey = diffieHellman.DeriveKeyMaterial(publicCng.PublicKey);
            }
        }

        return derivedKey;
    }
}
