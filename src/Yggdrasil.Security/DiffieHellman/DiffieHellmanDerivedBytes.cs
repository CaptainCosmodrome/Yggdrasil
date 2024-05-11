using System.Security.Cryptography;

namespace Yggdrasil.Security.DiffieHellman;
public class DiffieHellmanDerivedBytes(byte[] derivedKey) : DeriveBytes
{
    public override byte[] GetBytes(int cb)
    {
        return derivedKey.Take(cb).ToArray();
    }

    public override void Reset()
    {
        throw new NotImplementedException();
    }
}
