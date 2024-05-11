using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Yggdrasil.Security.DiffieHellman;
public static class DiffieHellmanHelper
{
    /// <summary>
    /// Get a derived encryption key for a diffie-hellman key exchange
    /// </summary>
    /// <param name="sharedCertificate">The certificate shared with you (public key)</param>
    /// <param name="ownedCertificate">The certificate you own (private key)</param>
    /// <returns></returns>
    public static byte[] GetDerivedKey(X509Certificate2 sharedCertificate, X509Certificate2 ownedCertificate)
    {
        byte[] derivedKey;

        using (var privateKey = (ECDsaCng)ownedCertificate.GetECDsaPrivateKey())
        using (var publicKey = (ECDsaCng)sharedCertificate.GetECDsaPublicKey())
        {
            var publicParams = publicKey.ExportParameters(false);
            var privateParams = privateKey.ExportParameters(true);

            using (var publicCng = ECDiffieHellmanCng.Create(publicParams))
            using (var diffieHellman = ECDiffieHellmanCng.Create(privateParams))
            {
                derivedKey = diffieHellman.DeriveKeyMaterial(publicCng.PublicKey);
            }
        }

        return derivedKey;
    }

    public static byte[] GetDerivedKey2(X509Certificate2 sharedCertificate, X509Certificate2 ownedCertificate)
    {
        byte[] derivedKey;

        using var publicDiffie = sharedCertificate.GetECDiffieHellmanPublicKey();
        using var privateDiffie = ownedCertificate.GetECDiffieHellmanPublicKey();

        derivedKey = privateDiffie.DeriveKeyMaterial(publicDiffie.PublicKey);

        return derivedKey;
    }

    public static byte[] GetDerivedKey(ECDsa publicKey, ECDsa privateKey)
    {
        byte[] derivedKey;

        var publicParams = publicKey.ExportParameters(false);

        using var publicCng = ECDiffieHellmanCng.Create(publicParams);
        using var diffieHellman = new ECDiffieHellmanCng(((ECDsaCng)privateKey).Key);
        
        derivedKey = diffieHellman.DeriveKeyMaterial(publicCng.PublicKey);

        return derivedKey;
    }
}
