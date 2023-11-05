using System.Security.Cryptography;

namespace Yggdrasil.Core.Interfaces;

public interface ICryptographicKeyProvider
{
    DeriveBytes CreateKey(string key, string salt, int iterations = 1000);
}
