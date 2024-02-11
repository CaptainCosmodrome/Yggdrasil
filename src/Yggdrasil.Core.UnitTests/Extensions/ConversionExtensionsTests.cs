using System;
using Yggdrasil.Core.Extensions;

namespace Yggdrasil.Core.UnitTests.Helpers;

[TestFixture]
public class ConversionExtensionsTests
{
    [Test]
    public void ChangeType_ToInt_ReturnsConvertedValue()
    {
        object value = "123";

        var result = value.ChangeType<int>();

        result.ShouldBe(123);
    }

    [Test]
    public void ChangeType_ToNullableInt_WhenNotNull_ReturnsConvertedValue()
    {
        object value = "123";

        var result = value.ChangeType<int?>();

        result.ShouldBe(123);
    }

    [Test]
    public void ChangeType_ToNullableInt_WhenEmptyString_ReturnsConvertedValue()
    {
        object value = "";

        var result = value.ChangeType<int?>();

        result.ShouldBeNull();
    }

    [Test]
    public void ChangeType_ToNullableInt_WhenNull_ReturnsConvertedValue()
    {
        object value = null;

        var result = value.ChangeType<int?>();

        result.ShouldBeNull();
    }

    [Test]
    public void ChangeType_ToLong_ReturnsConvertedValue()
    {
        object value = "1234567890";

        var result = value.ChangeType<long>();

        result.ShouldBe(1234567890L);
    }

    [Test]
    public void ChangeType_ToDateTime_ReturnsConvertedValue()
    {
        object value = new DateTime(2003, 1, 5);

        var result = value.ChangeType<DateTime>();

        result.Year.ShouldBe(2003);
        result.Month.ShouldBe(1);
        result.Day.ShouldBe(5);
    }
}

