namespace Vrsndl.Authorization.Client;

internal static class VrsndlAuthorizationOptionsExtentions
{
    private static ILogger? _logger = null;
    private static ILogger Logger
    {
        get
        {
            _logger ??= VrsndlLoggerFactory.CreateLogger(nameof(JwtValidationOptionsExtensions));
            return _logger;
        }
    }

    public static bool CheckPublicKeyFile(this VrsndlAuthorizationOptions authorizationOptions)
    {
        // No file, check fails
        string? publicKeyFile = authorizationOptions.PemFile;
        if (string.IsNullOrEmpty(publicKeyFile))
            return false;

        // If not full path then try to find the file
        if (!Path.IsPathFullyQualified(publicKeyFile))
        {
            publicKeyFile = FileExtensions.FindFullFilePath(publicKeyFile);
            // Tried to find the file, but not found
            if (string.IsNullOrEmpty(publicKeyFile))
                return false;
        }

        if (!File.Exists(publicKeyFile))
            return false;

        try
        {
            var bytes = File.ReadAllBytes(publicKeyFile);
            RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(bytes, out _);
            return true;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Exception while checking public key file");
            //throw new NotImplementedException();
            return false;
        }
    }

    public static List<SecurityKey> GetSecurityKeys(this IList<VrsndlAuthorizationOptions>? authorizationsOptions)
    {
        List<SecurityKey> securityKeys = new List<SecurityKey>();
        if (authorizationsOptions == null)
            return securityKeys;

        foreach (var authorizationsOption in authorizationsOptions)
        {
            var securityKey = authorizationsOption.GetSecurityKey();
            if (securityKey != null)
                securityKeys.Add(securityKey);
        }

        return securityKeys;
    }

    public static SecurityKey? GetSecurityKey(this VrsndlAuthorizationOptions? authorizationOptions)
    {
        if (authorizationOptions == null || authorizationOptions.Ignore == true)
            return null;

        if (authorizationOptions.Algorithm.IsSymmetricAlgorithm() && !string.IsNullOrEmpty(authorizationOptions.Secret))
        {
            var bytes = Encoding.ASCII.GetBytes(authorizationOptions.Secret);
            return new SymmetricSecurityKey(bytes);
        }

        if (authorizationOptions.Algorithm.IsASymmetricAlgorithm() && !string.IsNullOrEmpty(authorizationOptions.PemFile))
        {
            return authorizationOptions.PemFile.GetSecurityKeyFromPemFile();
        }

        if (authorizationOptions.Algorithm.IsASymmetricAlgorithm() && !string.IsNullOrEmpty(authorizationOptions.PublicKey))
        {
            return authorizationOptions.PublicKey.GetSecurityKeyFromPublicKey();
        }

        return null;
    }

    public static SigningCredentials? GetSigningCredentials(this VrsndlAuthorizationOptions authorizationOptions)
    {
        if (authorizationOptions.Algorithm == null)
            return null;

        var securityKey = authorizationOptions.GetSecurityKey();

        if (authorizationOptions.Algorithm.IsSymmetricAlgorithm() && securityKey != null)
        {
            var algorithm = authorizationOptions.Algorithm.ToUpper().Replace("HMACSHA", "HS");
            return new SigningCredentials(securityKey, algorithm);
        }

        if (authorizationOptions.Algorithm.IsASymmetricAlgorithm() && securityKey != null)
        {
            var algorithm = authorizationOptions.Algorithm.ToUpper().Replace("RSASHA", "RS");
            return new SigningCredentials(securityKey, algorithm);
        }

        return null;
    }

    public static bool ValidateAuthorizationOptions(this VrsndlAuthorizationOptions authorizationOptions, string? scheme, string? issuer, string? audience)
    {
        authorizationOptions.Scheme ??= scheme;
        authorizationOptions.Issuer ??= issuer;
        authorizationOptions.Audience ??= audience;

        if (!JwtAlgorithm.IsASymmetricAlgorithm(authorizationOptions.Algorithm) &&
            !JwtAlgorithm.IsSymmetricAlgorithm(authorizationOptions.Algorithm))
        {
            Logger.LogCritical("No validate signing algorithm found. Validat signing algorithms are:");
            Logger.LogCritical("Symetrical (using a secret): HMACSHA265, HMACSHA384, HMACSHA512");
            Logger.LogCritical("ASymetrical (using a public key): RSASHA265, RSASHA384, RSASHA512");

            if (authorizationOptions.Secret != null)
            {
                Logger.LogInformation("A secret is given, assuming HMACSAH256");
                authorizationOptions.Algorithm = "HMACSHA265";
            }
            else
                return false;
        }

        return true;
    }
}
