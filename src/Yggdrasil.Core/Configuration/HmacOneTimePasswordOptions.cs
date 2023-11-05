namespace Yggdrasil.Core.Configuration
{
    public class HmacOneTimePasswordOptions
    {
        public int CodeDigits { get; set; } = 6;
        public bool AddCheckSum { get; set; } = false;
        public int? TruncationOffset { get; set; }
    }
}
