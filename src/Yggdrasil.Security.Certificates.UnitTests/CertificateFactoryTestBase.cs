using System.Security.Cryptography.X509Certificates;

namespace Yggdrasil.Security.Certificates.UnitTests;
[TestFixture]
public abstract class CertificateFactoryTestBase
{
    protected X509Store _caStore;
    protected X509Store _store;

    protected string _certName;
    protected string _issuerName;
    protected string _certFriendlyName;
    protected string _issuerFriendlyName;

    [SetUp]
    public void BeforeEachTest()
    {
        _certName = $"TEST_{Guid.NewGuid()}";
        _issuerName = $"TEST_ISSUER_{Guid.NewGuid()}";
        _certFriendlyName = "TEST_CERT";
        _issuerFriendlyName = "TEST_ISSUER";

        _caStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        _store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    }

    [TearDown]
    public void AfterEachTest()
    {
        if (_caStore.IsOpen)
        {
            var caSearch = _caStore.Certificates.Find(X509FindType.FindBySubjectName, _certName, false);

            foreach (var ca in caSearch)
            {
                _caStore.Remove(ca);
            }
        }

        if (_store.IsOpen)
        {
            var caSearch = _store.Certificates.Find(X509FindType.FindBySubjectName, _issuerName, false);

            foreach (var ca in caSearch)
            {
                _store.Remove(ca);
            }
        }
    }
}
