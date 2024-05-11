using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Certificates.Algorithms;
using Yggdrasil.Security.Certificates.Factories;
using Yggdrasil.Security.Certificates.Interfaces;
using Yggdrasil.Security.Cryptography;

namespace Yggdrasil.Security.UnitTests.DiffieHellman;
[TestFixture]
public class DiffieHellmanCryptographerTests
{
    private IDiffieHellmanCryptographer _target;

    private ICertificateFactory _certificateFactory;
    

    private string _payload;

    [SetUp]
    public void BeforeEachTest()
    {
        _payload = Guid.NewGuid().ToString();

        _certificateFactory = new ECDsaCertificateFactory();
        _target = new DiffieHellmanCryptographer();
    }

    [Test]
    public async Task EncryptAsync_WhenUsingDHDerivesKey_CanDecrypt()
    {
        var cert1 = _certificateFactory.GenerateCertificate(AlgorithmConstants.ECDsa384Sha256, "Test Certificate 1",
            TimeSpan.FromDays(77), "Test Cert 1");

        var cert2 = _certificateFactory.GenerateCertificate(AlgorithmConstants.ECDsa384Sha256, "Test Certificate 2",
            TimeSpan.FromDays(77), "Test Cert 2");

        var cipher = await _target.EncryptAsync(_payload, cert1, cert2);

        TestContext.Out.WriteLine(cipher);

        var result = await _target.DecryptAsync(cipher, cert2, cert1);

        result.ShouldBe(_payload);
    }
}
