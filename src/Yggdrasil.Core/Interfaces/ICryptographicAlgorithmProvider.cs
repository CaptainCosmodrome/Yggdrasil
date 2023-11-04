using System.Security.Cryptography;

namespace Yggdrasil.Core.Interfaces;

public interface ICryptographicAlgorithmProvider
{
    SymmetricAlgorithm CreateSymmetricAlgorithm(string key, string salt, int iterations = 1000);
}
