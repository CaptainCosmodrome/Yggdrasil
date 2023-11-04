using System.Security.Cryptography;

namespace Yggdrasil.Core.Interfaces;

public interface ICryptographicKeyGenerator
{
    DeriveBytes CreateKey(string key, string salt, int iterations = 1000);
}
