namespace Yggdrasil.Core.Extensions;

public static class ConversionExtensions
{
    public static TValue ChangeType<TValue>(this object? value, TValue defaultValue = default)
    {
        var innerType = Nullable.GetUnderlyingType(typeof(TValue));

        if (innerType != null)
        {
            if (value == null || value == string.Empty)
            {
                return defaultValue;
            }

            return (TValue)Convert.ChangeType(value, innerType);
        }
        else
        {
            if (value == null || value == string.Empty)
            {
                return defaultValue;
            }

            return (TValue)Convert.ChangeType(value, typeof(TValue));
        }
    }

    public static TValue SafeChangeType<TValue>(this object? value, TValue defaultValue = default)
    {
        try
        {
            return value.ChangeType(defaultValue);
        }
        catch (Exception e)
        {
            return defaultValue;
        }
    }
}

