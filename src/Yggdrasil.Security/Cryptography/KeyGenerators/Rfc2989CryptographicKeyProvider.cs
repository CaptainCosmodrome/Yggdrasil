using System.Security.Cryptography;
using System.Text;
using Yggdrasil.Core.Interfaces;

namespace Yggdrasil.Security.Cryptography.KeyGenerators;

public class Rfc2989CryptographicKeyProvider : ICryptographicKeyProvider
{
    public DeriveBytes CreateKey(string key, string salt, int iterations = 1000)
    {
        byte[] saltData = Encoding.UTF8.GetBytes(salt);

        byte[] passwordData = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(key));

        return new Rfc2898DeriveBytes(passwordData, saltData, iterations);
    }
}
