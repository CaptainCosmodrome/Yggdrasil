using System.Security.Cryptography;
using System.Text;
using Yggdrasil.Core.Enums;
using Yggdrasil.Core.Interfaces;

namespace Yggdrasil.Security.OneTimePassword;

/// <summary>
/// Create a numeric hmac-based one-time password using the RFC-4226 standards
/// </summary>
/// <see cref="http://tools.ietf.org/html/rfc4226"/>
public class Rfc4226OneTimePasswordProvider : IHmacBasedOneTimePasswordProvider
{
    // These are used to calculate the check-sum digits.
    //                                    0  1  2  3  4  5  6  7  8  9
    private static int[] doubleDigits = { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };

    //                                   0 1  2   3    4     5      6       7        8
    private static int[] DIGITS_POWER = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };

    /// <summary>
    /// Generate a numeric Hmac-based One Time Password
    /// </summary>
    /// <param name="secret">the shared secret</param>
    /// <param name="movingFactor">the counter, time, or other value that changes on a per use basis.</param>
    /// <param name="codeDigits">the number of digits in the OTP, not including the checksum, if any.</param>
    /// <param name="addChecksum">a flag that indicates if a checksum digit should be appended to the OTP.</param>
    /// <param name="truncationOffset">the offset into the MAC result to begin truncation.  If this 
    /// value is out of the range of 0 ... 15, then dynamic truncation  will be used. Dynamic 
    /// truncation is when the last 4 bits of the last byte of the MAC are used to determine the 
    /// start offset.</param>
    /// <returns>A numeric String in base 10 that includes {@link codeDigits} digits plus the optional checksum digit if requested.</returns>
    public string CreateOneTimePassword(string secret, int movingFactor, int codeDigits = 6, bool addChecksum = true, int truncationOffset = 4)
    {
        return CreateOneTimePassword(Encoding.UTF8.GetBytes(secret), movingFactor, codeDigits, addChecksum, truncationOffset);
    }

    /// <summary>
    /// Generate a numeric One Time Password
    /// </summary>
    /// <param name="secret">the shared secret</param>
    /// <param name="movingFactor">the counter, time, or other value that changes on a per use basis.</param>
    /// <param name="codeDigits">the number of digits in the OTP, not including the checksum, if any.</param>
    /// <param name="addChecksum">a flag that indicates if a checksum digit should be appended to the OTP.</param>
    /// <param name="truncationOffset">the offset into the MAC result to begin truncation.  If this 
    /// value is out of the range of 0 ... 15, then dynamic truncation  will be used. Dynamic 
    /// truncation is when the last 4 bits of the last byte of the MAC are used to determine the 
    /// start offset.</param>
    /// <returns>A numeric String in base 10 that includes {@link codeDigits} digits plus the optional checksum digit if requested.</returns>
    public string CreateOneTimePassword(byte[] secret, long movingFactor, int codeDigits = 6, bool addChecksum = true, int truncationOffset = 4)
    {
        // put movingFactor value into text byte array
        string result = String.Empty;
        int digits = addChecksum ? (codeDigits + 1) : codeDigits;
        byte[] text = new byte[8];

        for (int i = text.Length - 1; i >= 0; i--)
        {
            text[i] = (byte)(movingFactor & 0xff);
            movingFactor >>= 8;
        }

        // compute hmac hash
        byte[] hash = CreateSha1Hmac(secret, text);

        // put selected bytes into result int
        int offset = hash[hash.Length - 1] & 0xf;

        if ((0 <= truncationOffset) && (truncationOffset < (hash.Length - 4)))
        {
            offset = truncationOffset;
        }

        int binary =
            ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[codeDigits];

        if (addChecksum)
        {
            otp = (otp * 10) + CalculateChecksum(otp, codeDigits);
        }

        result = otp.ToString();

        while (result.Length < digits)
        {
            result = "0" + result;
        }

        return result;
    }

    public OneTimePasswordValidationResult ValidateOneTimePassword(string hotp, string secret, int movingFactor, int codeDigits = 6, bool addChecksum = true, int offset = 4)
    {
        //check the length to make sure it is right
        if ((addChecksum && hotp.Length != codeDigits + 1) || (!addChecksum && hotp.Length != codeDigits))
        {
            return OneTimePasswordValidationResult.InvalidLength;
        }

        //make sure that the hotp is only numbers
        long value;

        if (!long.TryParse(hotp, out value))
        {
            return OneTimePasswordValidationResult.Invalid;
        }

        //if the checksum was used, test to make sure the checksum is valid
        if (addChecksum)
        {
            int checkSum;

            //make sure the checksum is numeric
            if (!int.TryParse(hotp.Substring(codeDigits), out checkSum))
            {
                return OneTimePasswordValidationResult.InvalidChecksum;
            }

            //calculate the checksum from the hotp
            int calculatedCheckSum = GetCheckSum(hotp, codeDigits);

            //compare the computed checksum with the actual checksum
            if (checkSum != calculatedCheckSum)
            {
                return OneTimePasswordValidationResult.InvalidChecksum;
            }
        }

        //rebuild the hotp
        var testHotp = CreateOneTimePassword(Encoding.UTF8.GetBytes(secret), movingFactor, codeDigits, addChecksum, offset);

        //compare the test hotp with the actual hotp
        if (testHotp.Equals(hotp, StringComparison.OrdinalIgnoreCase))
        {
            return OneTimePasswordValidationResult.Valid;
        }

        //no match found but hotp was valid
        return OneTimePasswordValidationResult.NoMatch;
    }

    /// <summary>
    /// calculate the checksum from a hotp
    /// </summary>
    /// <param name="hotp">the hotp to calculate the checksum</param>
    /// <returns></returns>
    protected static int GetCheckSum(string hotp, int codeDigits)
    {
        if (!long.TryParse(hotp, out long value))
        {
            return -1;
        }

        //only take the length of the hotp.  If the checksum is used, the total length will be hotpLength + 1
        value = Convert.ToInt64(hotp.Substring(0, codeDigits));

        return CalculateChecksum(value, codeDigits);
    }

    /// <summary>
    /// Calculates the checksum using the credit card algorithm.
    /// This algorithm has the advantage that it detects any single
    /// mistyped digit and any single transposition of
    /// adjacent digits.
    /// </summary>
    /// <param name="num">the number to calculate the checksum for</param>
    /// <param name="digits">number of significant places in the number</param>
    /// <returns></returns>
    protected static int CalculateChecksum(long num, int digits)
    {
        bool doubleDigit = true;
        int total = 0;
        while (0 < digits--)
        {
            int digit = (int)(num % 10);
            num /= 10;
            if (doubleDigit)
            {
                digit = doubleDigits[digit];
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        int result = total % 10;
        if (result > 0)
        {
            result = 10 - result;
        }
        return result;
    }

    /// <summary>
    /// Hash using HMAC-SHA 1
    /// </summary>
    /// <param name="keyBytes"></param>
    /// <param name="text"></param>
    /// <returns></returns>
    private static byte[] CreateSha1Hmac(byte[] keyBytes, byte[] text)
    {
        HMAC alg = new HMACSHA1(keyBytes);

        return alg.ComputeHash(text);
    }
}

