using System.Security.Cryptography.X509Certificates;
using Yggdrasil.Security.Certificates.Algorithms;
using Yggdrasil.Security.Certificates.Factories;
using Yggdrasil.Security.Certificates.Interfaces;

namespace Yggdrasil.Security.Certificates.UnitTests;

[TestFixture]
public class EcdsaSigningCertificateFactoryTests
{
    private ICertificateFactory _target;

    private X509Store _caStore;

    private X509Certificate2 _caCertificate;
    private string _name;
    private string _friendlyName;

    [SetUp]
    public void BeforeEachTest()
    {
        _name = $"TEST_{Guid.NewGuid()}";
        _friendlyName = $"TEST_AUTH_{Guid.NewGuid()}";
   
        _caStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);

        _target = new ECDsaCertificateFactory();
    }

    [TearDown]
    public void AfterEachTest()
    {
        if (_caStore.IsOpen)
        {
            var caSearch = _caStore.Certificates.Find(X509FindType.FindBySubjectName, _name, false);

            foreach (var ca in caSearch)
            {
                _caStore.Remove(ca);
            }
        }

        _caCertificate.Dispose();
        _caStore.Dispose();
    }

    [Test]
    public void GenerateSigningCertificate_AfterAddingToStore_CanBuildChain()
    {
        _caCertificate = _target.GenerateCertificate(AlgorithmConstants.ECDsa384Sha256, _name, TimeSpan.FromDays(356), _friendlyName);

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

        Assert.That(chainBuilt, "Chain");
        Assert.That(_caCertificate.Verify());
    }
}
