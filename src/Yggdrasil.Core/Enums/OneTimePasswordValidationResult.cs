namespace Yggdrasil.Core.Enums;

public enum OneTimePasswordValidationResult
{
    Invalid = 0,
    Valid = 1,
    InvalidLength = 2,
    InvalidChecksum = 3,
    Expired = 4,
    NoMatch = 5
}

