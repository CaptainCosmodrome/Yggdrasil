using System.Security.Cryptography;
using Yggdrasil.Core.Enums;

namespace Yggdrasil.Security.Certificates.Algorithms;
public struct AlgorithmDefinition(AlgorithmEnum algorithm, int keyStrength, HashAlgorithmName hashAlgorithm, string? oid = null)
{
    public AlgorithmEnum Algorithm { get; private set; } = algorithm;
    public int KeyStrength { get; private set; } = keyStrength;
    public HashAlgorithmName HashAlgorithm { get; private set; } = hashAlgorithm;
    public string SigningAlgorithm { get; private set; } = $"{algorithm:f}with{hashAlgorithm}";
    public string? Oid { get; private set; } = oid;
}
