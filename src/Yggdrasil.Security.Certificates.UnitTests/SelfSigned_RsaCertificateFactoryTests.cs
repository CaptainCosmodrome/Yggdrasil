using System.Security.Cryptography.X509Certificates;
using Yggdrasil.Security.Certificates.Algorithms;
using Yggdrasil.Security.Certificates.Factories;
using Yggdrasil.Security.Certificates.Interfaces;

namespace Yggdrasil.Security.Certificates.UnitTests;

[TestFixture]
public class SelfSigned_RsaCertificateFactoryTests
{
    private ICertificateFactory _target;

    private X509Store _caStore;

    private X509Certificate2 _caCertificate;
    private string _issuerName;
    private string _issuerFriendlyName;

    [SetUp]
    public void BeforeEachTest()
    {
        _issuerName = $"TEST_{Guid.NewGuid()}";
        _issuerFriendlyName = $"TEST_AUTH_{Guid.NewGuid()}";
   
        _caStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);

        _target = new RsaCertificateFactory();
    }

    [TearDown]
    public void AfterEachTest()
    {
        if (_caStore.IsOpen)
        {
            var caSearch = _caStore.Certificates.Find(X509FindType.FindBySubjectName, _issuerName, false);

            foreach (var ca in caSearch)
            {
                _caStore.Remove(ca);
            }
        }
    }

    [Test]
    public void GenerateSigningCertificate_AfterAddingToStore_CanBuildChain()
    {
        _caCertificate = _target.GenerateCertificate(AlgorithmConstants.Rsa4096Sha256, _issuerName, TimeSpan.FromDays(356), _issuerFriendlyName);

        _caStore.Open(OpenFlags.ReadWrite);

        _caStore.Add(_caCertificate);
        
        var chain = new X509Chain
        {
            ChainPolicy =
            {
                RevocationMode = X509RevocationMode.NoCheck
            }
        };

        var chainBuilt = chain.Build(_caCertificate);

        if (!chainBuilt)
        {
            foreach (var status in chain.ChainStatus)
            {
                Assert.Warn(string.Format("Chain error: {0} {1}", status.Status, status.StatusInformation));
            }
        }

        Assert.IsTrue(chainBuilt, "Chain");
        Assert.IsTrue(_caCertificate.Verify());
    }
}
