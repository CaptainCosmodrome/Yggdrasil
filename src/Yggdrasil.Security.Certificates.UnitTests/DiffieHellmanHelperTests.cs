using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Certificates.Algorithms;
using Yggdrasil.Security.Certificates.Factories;
using Yggdrasil.Security.Certificates.Interfaces;
using Yggdrasil.Security.Cryptography;
using Yggdrasil.Security.Cryptography.AlgorithmProviders;
using Yggdrasil.Security.DiffieHellman;

namespace Yggdrasil.Security.Certificates.UnitTests;
[TestFixture]
public class DiffieHellmanHelperTests
{
    private ICertificateFactory _certificateFactory;
    private ICryptographer _cryptographer;

    private string _payload;

    public void BeforeEachTest()
    {
        _payload = Guid.NewGuid().ToString();

        _certificateFactory = new ECDsaCertificateFactory();
    }

    public void test()
    {
        var cert1 = _certificateFactory.GenerateCertificate(AlgorithmConstants.ECDsa384Sha256, "Test Certificate 1",
            TimeSpan.FromDays(1), "Test Cert 1");

        var cert2 = _certificateFactory.GenerateCertificate(AlgorithmConstants.ECDsa384Sha256, "Test Certificate 2",
            TimeSpan.FromDays(1), "Test Cert 2");

        var encryptionKey = DiffieHellmanHelper.GetDerivedKey(cert1, cert2);


    }
}
