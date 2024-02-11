using Yggdrasil.Core.Enums;
using Yggdrasil.Security.Certificates.Algorithms;

namespace Yggdrasil.Security.Certificates.Extensions;
public static class AlgorithmDefinitionExtensions
{
    public static bool IsRsaAlgorithm(this AlgorithmDefinition algorithm)
    {
        return algorithm.Algorithm == AlgorithmEnum.Rsa;
    }

    public static bool IsECDsaAlgorithm(this AlgorithmDefinition algorithm)
    {
        return algorithm.Algorithm == AlgorithmEnum.ECDSA;
    }
}
