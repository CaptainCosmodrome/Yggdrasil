using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Yggdrasil.Core.Enums;
using Yggdrasil.Security.Certificates.Algorithms;
using Yggdrasil.Security.Certificates.Factories;
using Yggdrasil.Security.Certificates.Interfaces;

namespace Yggdrasil.Security.Certificates.UnitTests;

[TestFixture]
public class EcdsaCertificateFactoryTests : CertificateFactoryTestBase
{
    private ICertificateFactory _target;

    [SetUp]
    public new void BeforeEachTest()
    {
        base.BeforeEachTest();

        _target = new ECDsaCertificateFactory();
    }

    [NonParallelizable]
    [TestCaseSource(nameof(GetECDsaAlgorithms))]
    public void GenerateCertificate_ProvidedAlgorithm_IsValid(AlgorithmDefinition algorithm)
    {
        TestContext.Out.WriteLine($"{algorithm.Algorithm:f} {algorithm.KeyStrength} {algorithm.HashAlgorithm}");

        var issuer = _target.GenerateCertificate(algorithm, _issuerName, TimeSpan.FromDays(365), _issuerFriendlyName);

        var certificate = _target.GenerateCertificate(algorithm, _certName, TimeSpan.FromDays(365), _certFriendlyName, issuer);

        _caStore.Open(OpenFlags.ReadWrite);
        _store.Open(OpenFlags.ReadWrite);

        _caStore.Add(issuer);
        _store.Add(certificate);

        var chain = new X509Chain
        {
            ChainPolicy =
            {
                RevocationMode = X509RevocationMode.NoCheck
            }
        };

        var chainBuilt = chain.Build(certificate);

        if (!chainBuilt)
        {
            foreach (var status in chain.ChainStatus)
            {
                Assert.Warn(string.Format("Chain error: {0} {1}", status.Status, status.StatusInformation));
            }
        }

        Assert.That(chainBuilt, "Chain");
    }

    public static IEnumerable<AlgorithmDefinition> GetECDsaAlgorithms()
    {
        return typeof(AlgorithmConstants)
            .GetFields(BindingFlags.Public |BindingFlags.Static)
            .Where(fld => fld.FieldType == typeof(AlgorithmDefinition))
            .Select(fld => fld.GetValue(null) as AlgorithmDefinition?)
            .Where(algo => algo.HasValue)
            .Select(algo => algo.Value)
            .Where(algo => algo.Algorithm == AlgorithmEnum.ECDSA)
            .ToList();
    }
}
