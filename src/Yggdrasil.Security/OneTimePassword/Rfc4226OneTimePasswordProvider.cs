using Yggdrasil.Core.Configuration;
using Yggdrasil.Core.Enums;
using Yggdrasil.Core.Interfaces;
using Yggdrasil.Security.Helpers;

namespace Yggdrasil.Security.OneTimePassword;

/// <summary>
/// Create a numeric hmac-based one-time password using the RFC-4226 standards
/// </summary>
/// <see cref="http://tools.ietf.org/html/rfc4226"/>
public class Rfc4226OneTimePasswordProvider
    (HmacOneTimePasswordOptions options = null) : IHmacBasedOneTimePasswordProvider
{
    protected int CodeDigits { get; private set; } = options?.CodeDigits ?? 6;
    protected bool AddCheckSum { get; private set; } = options?.AddCheckSum ?? false;
    protected int TruncationOffset { get; private set; } = options?.TruncationOffset ?? 4;

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
    public string CreateOneTimePassword(string secret, int movingFactor, int? codeDigits = null, bool? addChecksum = null, int? truncationOffset = null)
    {
        return Rfc4226Helper.CreateRfc4226HotpBasedOneTimePassword(secret, movingFactor, codeDigits ?? CodeDigits, addChecksum ?? AddCheckSum,
            truncationOffset ?? TruncationOffset);
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
    public string CreateOneTimePassword(byte[] secret, long movingFactor, int? codeDigits = null, bool? addChecksum = null, int? truncationOffset = null)
    {
        return Rfc4226Helper.CreateRfc4226HotpBasedOneTimePassword(secret, movingFactor, codeDigits ?? CodeDigits, addChecksum ?? AddCheckSum,
            truncationOffset ?? TruncationOffset);
    }

    /// <summary>
    /// Validate a numeric hmac-based one time password
    /// </summary>
    /// <param name="hotp">the hotp value to validate</param>
    /// <param name="secret">the shared secret</param>
    /// <param name="movingFactor">the counter, time, or other value that changes on a per use basis.</param>
    /// <param name="codeDigits">the number of digits in the OTP, not including the checksum, if any.</param>
    /// <param name="addChecksum">a flag that indicates if a checksum digit should be appended to the OTP.</param>
    /// <param name="truncationOffset">the offset into the MAC result to begin truncation.  If this 
    /// value is out of the range of 0 ... 15, then dynamic truncation  will be used. Dynamic 
    /// truncation is when the last 4 bits of the last byte of the MAC are used to determine the 
    /// start offset.</param>
    /// <returns>OneTimePasswordValidationResult (excluding Expired)</returns>
    public OneTimePasswordValidationResult ValidateOneTimePassword(string hotp, string secret, int movingFactor, int? codeDigits = null, bool? addChecksum = null, int? truncationOffset = null)
    {
        return Rfc4226Helper.ValidateRfc4226HotpBasedOneTimePassword(hotp, secret, movingFactor, codeDigits ?? CodeDigits, addChecksum ?? AddCheckSum,
            truncationOffset ?? TruncationOffset);
    }
}

