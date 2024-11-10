namespace Vrsndl.Authorization.Client;

public static class JwtAlgorithm
{
    private static IList<string> SymmetricAlgorithms = new List<string>()
    {
        "HS256", "HS384", "HS512"
    };
    private static IList<string> ASymmetricAlgorithms = new List<string>()
    {
        "RS256", "RS384", "RS512"
    };

    public static bool IsSymmetricAlgorithm(this string? algorithm)
    {
        if (algorithm == null)
            return false;

        var a = algorithm.ToUpper().Replace("HMACSHA", "HS");
        return SymmetricAlgorithms.Contains(a);
    }

    public static bool IsASymmetricAlgorithm(this string? algorithm)
    {
        if (algorithm == null)
            return false;

        var a = algorithm.ToUpper().Replace("RSASHA", "RS");
        return ASymmetricAlgorithms.Contains(a);
    }

    public static bool DefaultAlgorithmValidator(
            string algorithm,
            SecurityKey securityKey,
            SecurityToken securityToken,
            TokenValidationParameters validationParameters)
    {
        if (algorithm == null)
            return false;

        // RSxxx or HSxxx algorithms are accepted, all others are rejected.
        if (IsASymmetricAlgorithm(algorithm) || IsSymmetricAlgorithm(algorithm))
            return true;

        return false;
    }
}
