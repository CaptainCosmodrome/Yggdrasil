using System.Security.Cryptography;
using Yggdrasil.Core.Enums;

namespace Yggdrasil.Security.Certificates.Algorithms;
public static class AlgorithmConstants
{
    public static readonly AlgorithmDefinition ECDsa384Sha256 = new(AlgorithmEnum.ECDSA, 384, HashAlgorithmName.SHA256, "1.2.840.10045.4.3.2");
    public static readonly AlgorithmDefinition ECDsa521Sha256 = new(AlgorithmEnum.ECDSA, 521, HashAlgorithmName.SHA256, "1.2.840.10045.4.3.2");
    public static readonly AlgorithmDefinition ECDsa384Sha384 = new(AlgorithmEnum.ECDSA, 384, HashAlgorithmName.SHA384, "1.2.840.10045.4.3.3");
    public static readonly AlgorithmDefinition ECDsa521Sha384 = new(AlgorithmEnum.ECDSA, 521, HashAlgorithmName.SHA384, "1.2.840.10045.4.3.3");
    public static readonly AlgorithmDefinition ECDsa384Sha512 = new(AlgorithmEnum.ECDSA, 384, HashAlgorithmName.SHA512, "1.2.840.10045.4.3.4");
    public static readonly AlgorithmDefinition ECDsa521Sha512 = new(AlgorithmEnum.ECDSA, 521, HashAlgorithmName.SHA512, "1.2.840.10045.4.3.4");

    public static readonly AlgorithmDefinition Rsa1024Sha256 = new(AlgorithmEnum.Rsa, 1024, HashAlgorithmName.SHA256);
    public static readonly AlgorithmDefinition Rsa2048Sha256 = new(AlgorithmEnum.Rsa, 2048, HashAlgorithmName.SHA256);
    public static readonly AlgorithmDefinition Rsa4096Sha256 = new(AlgorithmEnum.Rsa, 4096, HashAlgorithmName.SHA256);
    public static readonly AlgorithmDefinition Rsa1024Sha512 = new(AlgorithmEnum.Rsa, 1024, HashAlgorithmName.SHA512);
    public static readonly AlgorithmDefinition Rsa2048Sha512 = new(AlgorithmEnum.Rsa, 2048, HashAlgorithmName.SHA512);
    public static readonly AlgorithmDefinition Rsa4096Sha512 = new(AlgorithmEnum.Rsa, 4096, HashAlgorithmName.SHA512);
}
