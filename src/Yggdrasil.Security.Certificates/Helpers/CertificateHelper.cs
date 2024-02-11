using System.Text;
using Yggdrasil.Security.Helpers;

namespace Yggdrasil.Security.Certificates.Helpers;
public static class CertificateHelper
{
    public static byte[] GenerateSerialNumber(string name)
    {
        return Encoding.UTF8.GetBytes(Rfc6238Helper.Rfc6238(Encoding.UTF8.GetBytes(name), 
            DateTime.UtcNow, 
            TimeSpan.FromSeconds(1), 
            14));
    }
}
