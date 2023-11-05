using System.Security.Cryptography;
using System.Text;
using Yggdrasil.Core.Enums;

namespace Yggdrasil.Security.Helpers
{
    public class Rfc6238Helper
    {
        private const long unixEpochTicks = 621355968000000000L;
        private const long ticksToSeconds = 10000000L;

        public static string Rfc6238(byte[] secret, DateTime timestamp, TimeSpan stepDuration, int codeDigits = 6,
            TotpHashMode hashMode = TotpHashMode.Sha1)
        {
            return Rfc6238(secret, timestamp.Ticks, (int)stepDuration.TotalSeconds, codeDigits, hashMode);
        }

        public static string Rfc6238(byte[] secret, long timestamp, int stepDurationInSeconds = 30, int codeDigits = 6, TotpHashMode hashMode = TotpHashMode.Sha1)
        {
            var window = CalculateStep(timestamp, stepDurationInSeconds);

            var windowHex = $"{window:X}".PadLeft(16, '0').ToUpper();

            var data = Convert.FromHexString(windowHex);

            var hmac = ComputeHash(data, secret, hashMode);

            // put selected bytes into result int
            int offset = hmac[hmac.Length - 1] & 0xf;

            int binary =
                ((hmac[offset] & 0x7f) << 24) |
                ((hmac[offset + 1] & 0xff) << 16) |
                ((hmac[offset + 2] & 0xff) << 8) |
                (hmac[offset + 3] & 0xff);

            var truncatedValue = (int)(binary % (int)Math.Pow(10, codeDigits));

            return truncatedValue.ToString().PadLeft(codeDigits, '0');
        }

        /// <summary>
        /// Calculate the number of steps a timestamp is since unix epoch given a step duration in seconds
        /// </summary>
        /// <param name="timestamp"></param>
        /// <param name="stepDurationInSeconds"></param>
        /// <returns></returns>
        public static long CalculateStep(long timestamp, int stepDurationInSeconds = 30)
        {
            return ((timestamp - unixEpochTicks) / ticksToSeconds) / (long)stepDurationInSeconds;
        }

        public static byte[] ComputeHash(string data, byte[] secret, TotpHashMode hashMode = TotpHashMode.Sha1)
        {
            return ComputeHash(Encoding.UTF8.GetBytes(data), secret, hashMode);
        }

        public static byte[] ComputeHash(byte[] data, byte[] secret, TotpHashMode hashMode = TotpHashMode.Sha1)
        {
            byte[] hash = new byte[0];

            switch (hashMode)
            {
                case TotpHashMode.Sha1:
                    var hmacSha1 = new HMACSHA1(secret);
                    hash = hmacSha1.ComputeHash(data);
                    break;
                case TotpHashMode.Sha256:
                    var hmacSha256 = new HMACSHA256(secret);
                    hash = hmacSha256.ComputeHash(data);
                    break;
                case TotpHashMode.Sha512:
                    var hmacSha512 = new HMACSHA512(secret);
                    hash = hmacSha512.ComputeHash(data);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(hashMode), hashMode, null);
            }

            return hash;
        }
    }
}
