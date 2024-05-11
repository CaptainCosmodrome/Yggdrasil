using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.DiffieHellman;

namespace Yggdrasil.Security.Cryptography;
public class DiffieHellmanCryptographer : IDiffieHellmanCryptographer
{
    public async Task<string?> EncryptAsync(string text, X509Certificate2 publicKeyCertificate, X509Certificate2 privateKeyCertificate,
        CancellationToken cancellationToken = default)
    {
        byte[]? cipher = null;

        using var algorithm = CreateDiffieHellmanCryptoProvider(publicKeyCertificate, privateKeyCertificate);

        using var ms = new MemoryStream();
        using var encryptor = algorithm.CreateEncryptor();
        await using var crypto = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);

        await crypto.WriteAsync(Encoding.UTF8.GetBytes(text), cancellationToken);
        //await crypto.FlushFinalBlockAsync(cancellationToken);
        //await ms.FlushAsync(cancellationToken);

        cipher = ms.ToArray();

        return Encoding.UTF8.GetString(cipher);

        //string cipher = null;

        //using var algorithm = CreateDiffieHellmanCryptoProvider(publicKeyCertificate, privateKeyCertificate);
        //using var ms = new MemoryStream();
        //await using var crypto = new CryptoStream(ms, algorithm.CreateEncryptor(), CryptoStreamMode.Write);
        //await using var sw = new StreamWriter(crypto);

        //await sw.WriteAsync(text);
        //await sw.FlushAsync();
        //await crypto.FlushFinalBlockAsync(cancellationToken);
        //await ms.FlushAsync(cancellationToken);

        //cipher = Convert.ToBase64String(ms.GetBuffer(), 0, Convert.ToInt32(ms.Length));

        //return cipher;
    }

    public async Task<string?> DecryptAsync(string cipher, X509Certificate2 publicKeyCertificate, X509Certificate2 privateKeyCertificate)
    {
        string? result = null;

        using var algorithm = CreateDiffieHellmanCryptoProvider(publicKeyCertificate, privateKeyCertificate);

        using var ms = new MemoryStream();
        using var decryptor = algorithm.CreateDecryptor();
        await using var crypto = new CryptoStream(ms, decryptor, CryptoStreamMode.Write);

        var data = Encoding.UTF8.GetBytes(cipher);

        await crypto.WriteAsync(data, 0, data.Length);

        result = Encoding.UTF8.GetString(ms.ToArray());

        return result;

        //var rawData = Convert.FromBase64String(cipher);

        //string result = null;

        //using var algorithm = CreateDiffieHellmanCryptoProvider(publicKeyCertificate, privateKeyCertificate);
        //using var ms = new MemoryStream(rawData);
        //await using var crypto = new CryptoStream(ms, algorithm.CreateDecryptor(), CryptoStreamMode.Read);
        //using var sr = new StreamReader(crypto);

        //result = await sr.ReadToEndAsync();

        //return result;
    }

    private SymmetricAlgorithm CreateDiffieHellmanCryptoProvider(X509Certificate2 publicKeyCertificate, X509Certificate2 privateKeyCertificate)
    {
        var provider = new AesCryptoServiceProvider();

        provider.Padding = PaddingMode.Zeros;

        //var derivedKey = GetDerivedKey(publicKeyCertificate, privateKeyCertificate);

        //provider.KeySize = 384;
        //provider.BlockSize = 384;

        //provider.Key = derivedKey.GetBytes(provider.KeySize / 8);
        //provider.IV = derivedKey.GetBytes(provider.BlockSize / 8);

        provider.Key = DiffieHellmanHelper.GetDerivedKey(publicKeyCertificate,
            privateKeyCertificate);

        return provider;
    }

    //private DeriveBytes GetDerivedKey(X509Certificate2 publicKeyCertificate, X509Certificate2 privateKeyCertificate)
    //{
    //    var sharedSecretBytes = DiffieHellmanHelper.GetDerivedKey(publicKeyCertificate, 
    //        privateKeyCertificate);

    //    byte[] symmetricKey = new byte[256];
    //    digest.BlockUpdate(sharedSecretBytes, 0, sharedSecretBytes.Length);
    //    digest.DoFinal(symmetricKey, 0);

    //    return symmetricKey;
    //}
}
