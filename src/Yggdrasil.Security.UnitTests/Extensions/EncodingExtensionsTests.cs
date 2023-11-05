using System.Text;
using System.Web;
using Yggdrasil.Security.Extensions;

namespace Yggdrasil.Security.UnitTests.Extensions;

[TestFixture]
public class EncodingExtensionsTests
{
    [Test]
    public void Encode_Decode_CanDecodeEncodedValue()
    {
        var value = "this is a test";

        var base46Value = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));

        var encoded = base46Value.EncodeForQuerystring();

        var decoded = encoded.DecodeFromQuerystring();

        var result = Encoding.UTF8.GetString(Convert.FromBase64String(decoded));

        result.ShouldBe(value);
    }

    [Test]
    public async Task Encode_Decode_WhenEncodedValueHasSpace_ReturnsValidBase64String()
    {
        var encrypted = "nrUw45k/74sAku6+kOn8eg==";

        var encoded = encrypted.EncodeForQuerystring();

        await TestContext.Out.WriteLineAsync($"Encoded: {encoded}");

        //do this to mimic how sometimes the URL changes when it is used in a link and passes back through the server
        var uri = new Uri($"https://example.com?q={encoded}");
        var query = HttpUtility.ParseQueryString(uri.Query);

        var decoded = query["q"].DecodeFromQuerystring();

        Should.NotThrow(() => Convert.FromBase64String(decoded));
    }
}

