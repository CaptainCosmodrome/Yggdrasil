using System.Text;
using System.Web;

namespace Yggdrasil.Security.Extensions
{
    public static class EncodingExtensions
    {
        public static string EncodeForQuerystring(this string value)
        {
            var encoded = HttpUtility.UrlEncode(Encoding.UTF8.GetBytes(value));

            //in my experience, even though properly decoded, spaces (+) do not travel well from link to browser to code behind, and = are valid characters in a qs
            return encoded.Replace(" ", "@").Replace("+", "@");
        }

        public static string DecodeFromQuerystring(this string value)
        {
            var decoded = HttpUtility.UrlDecode(value.Replace("@", "+"));

            //in my experience, even though properly decoded, spaces (+) do not travel well from link to browser to code behind, and = are valid characters in a qs
            return decoded.Replace(" ", "+");
        }
    }
}
